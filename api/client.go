package alipay

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	//"time"
	"crypto/rand"
	"encoding/xml"
	"strconv"
	"time"
)

const (
	apigate  = "https://openapi.alipay.com/gateway.do"
	mapigate = "https://mapi.alipay.com/gateway.do"
	//for single query
	zhifubaopubkey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnxj/9qwVfgoUh/y2W89L6BkRAFljhNhgPdyPuBV64bfQNN1PjbCzkIM6qRdKBoLPXmKKMiFYnkd6rAoprih3/PrQEB/VsW8OoM8fxn67UDYuyBTqA23MML9q1+ilIZwBC2AQ2UBVOrFXfFl75p6/B5KsiNG9zpgmLCUYuLkxpLQIDAQAB`
)

//http://stackoverflow.com/questions/20655702/signing-and-decoding-with-rsa-sha-in-go
// loadPrivateKey loads an parses a PEM encoded private key file.
func loadZhifubaoKey() (Unsigner, error) {
	return parsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`))
}

func VerifyZhifubaoRes(params, sig string) (res bool, e error) {
	key, err := base64.StdEncoding.DecodeString(zhifubaopubkey)
	if err != nil {
		e = err
		return
	}
	re, err := x509.ParsePKIXPublicKey(key)
	pub := re.(*rsa.PublicKey)
	if err != nil {
		e = err
		return
	}
	h := sha1.New()
	h.Write([]byte(params))
	digest := h.Sum(nil)
	ds, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		e = err
		return
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, ds)
	if err == nil {
		res = true
	} else {
		e = err
	}
	return
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	pem, e := ioutil.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return parsePrivateKey(pem)
	//	return parsePrivateKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
	//	your private pem here
	//	bababababaab
	//-----END RSA PRIVATE KEY-----`))
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA1, d)
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha1.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA1, d, sig)
}

type ZhifubaoApiClient struct {
	Pid            string
	PrivatePemPath string
}

var (
	//charset = "utf-8"
	//sightype = "RSA"
	//version = "1.0"
	publicParams = map[string]string{
		//"charset": "utf-8",
		"_input_charset": "utf-8",
		"sign_type":      "RSA",
		"version":        "1.0",
	}
)

func CreateZhifubaoClient(pid, pemPath string) (client *ZhifubaoApiClient) {
	client = &ZhifubaoApiClient{
		Pid:            pid,
		PrivatePemPath: pemPath,
		//PrivatePemPath:"/Users/james/Dropbox/HAVE/zhifubao/rsa_private_key.pem",
	}
	return
}

func (c *ZhifubaoApiClient) sign(params map[string]string) (secret string) {
	//params["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	keys := []string{}
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kv := []string{}
	for _, k := range keys {
		kv = append(kv, k+"="+params[k])
	}
	signer, err := loadPrivateKey(c.PrivatePemPath)
	if err != nil {
		return
	}
	signed, err := signer.Sign([]byte(strings.Join(kv, "&")))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
	}
	secret = url.QueryEscape(base64.StdEncoding.EncodeToString(signed))
	return

}

func (c *ZhifubaoApiClient) CreateOrderByOrderId(ordId string) (res bool, e error) {
	params := publicParams
	params["app_id"] = c.Pid
	params["method"] = "alipay.trade.create"
	params["out_trade_no"] = ordId
	params["total_amount"] = "0.01"
	params["buyer_logon_id"] = ""
	//params["method"] = "alipay.pass.instance.update"
	//params["serial_number"] = ordId
	//params["channel_id"] = ordId
	params["sign"] = c.sign(params)
	form := url.Values{}
	for k, v := range params {
		form.Add(k, v)
	}
	log.Println(form)
	req, err := http.NewRequest("POST", apigate, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Println("a")
		log.Println(err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("b")
		log.Println(err)
		return
	}
	var dat map[string]interface{}
	json.Unmarshal(body, &dat)
	log.Println("c")
	log.Println(dat)
	return
}

func (c *ZhifubaoApiClient) QueryPayResByOrderId(ordId string) (res bool, response map[string]string, e error) {
	params := map[string]string{
		"_input_charset": "utf-8",
		"service":        "single_trade_query",
		"partner":        c.Pid,
		"out_trade_no":   ordId,
	}
	apiParams := c.signOfOneMethod(params)
	resp, err := http.Get(mapigate + "?" + apiParams)
	defer resp.Body.Close()
	if err != nil {
		log.Println(err)
		e = err
		return
	}
	if err != nil {
		log.Println(err)
		return
	}
	decoder := xml.NewDecoder(resp.Body)
	start := false
	sign := false
	var nodename string
	//parseRes := []string{}
	parseRes := map[string]string{}
	secret := ""
	for t, err := decoder.Token(); err == nil; t, err = decoder.Token() {
		switch token := t.(type) {
		case xml.StartElement:
			name := token.Name.Local
			if start {
				nodename = name
			}
			if name == "trade" {
				start = true
			} else if name == "sign" {
				sign = true
			}
		case xml.EndElement:
			if token.Name.Local == "trade" {
				start = false
			}
			break
		case xml.CharData:
			content := string([]byte(token))
			if start {
				//parseRes = append(parseRes, nodename + "=" + content)
				parseRes[nodename] = content
			} else if sign {
				secret = content
				sign = false
			}
		default:
			continue
		}
	}
	keys := []string{}
	for k, _ := range parseRes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	requestStr := []string{}
	for _, k := range keys {
		requestStr = append(requestStr, k+"="+parseRes[k])
	}
	verifyRes, err := VerifyZhifubaoRes(strings.Join(requestStr, "&"), secret)
	if !verifyRes {
		e = err
		return
	}
	response = parseRes
	res = ((parseRes["trade_status"] == "TRADE_SUCCESS") || (parseRes["trade_status"] == "TRADE_FINISHED"))
	return
}

//https://doc.open.alipay.com/doc2/detail.htm?spm=a219a.7629140.0.0.aQc9uV&treeId=59&articleId=103663&docType=1
func (c *ZhifubaoApiClient) GetMobilePayOrderString(ordId, notifyUrl, subject, detail string, price float64) string {
	priceStr := strconv.FormatFloat(price, 'f', 2, 64)
	params := map[string]string{
		"_input_charset": "utf-8",
		"service":        "mobile.securitypay.pay",
		"partner":        c.Pid,
		"notify_url":     notifyUrl,
		"out_trade_no":   ordId,
		"subject":        subject,
		"payment_type":   "1",
		"seller_id":      c.Pid,
		"total_fee":      priceStr,
		"body":           detail,
	}
	array := []string{}
	for k, v := range params {
		array = append(array, k+"="+("\""+v+"\""))
	}
	signer, err := loadPrivateKey(c.PrivatePemPath)
	if err != nil {
		return ""
	}
	signed, err := signer.Sign([]byte(strings.Join(array, "&")))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
	}
	secret := url.QueryEscape(base64.StdEncoding.EncodeToString(signed))
	return strings.Join(array, "&") + "&sign=\"" + secret + "\"&sign_type=\"RSA\""
}

func (c *ZhifubaoApiClient) signOfOneMethod(params map[string]string) (request string) {
	keys := []string{}
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	requestStr := []string{}
	for _, k := range keys {
		requestStr = append(requestStr, k+"="+params[k])
	}
	signer, err := loadPrivateKey(c.PrivatePemPath)
	if err != nil {
		return
	}
	signed, err := signer.Sign([]byte(strings.Join(requestStr, "&")))
	requestStr = append(requestStr, "sign="+url.QueryEscape(base64.StdEncoding.EncodeToString(signed)))
	requestStr = append(requestStr, "sign_type=RSA")
	request = strings.Join(requestStr, "&")
	return
}

func (c *ZhifubaoApiClient) GenerateRefundLinkByOrderId(price float64, orderId, sellerEmail, sellerId, explain string) (string, error) {
	mrand.Seed(time.Now().Unix())
	random := mrand.Intn(10000-1000) + 1000
	params := map[string]string{
		"_input_charset": "utf-8",
		"service":        "refund_fastpay_by_platform_pwd",
		"partner":        c.Pid,
		"seller_email":   sellerEmail,
		"seller_user_id": sellerId,
		"refund_date":    time.Now().Format("2006-01-02 15:04:05"),
		"batch_no":       time.Now().Format("20060102") + strconv.Itoa(random),
		"batch_num":      "1",
		"detail_data":    orderId + "^" + strconv.FormatFloat(price, 'f', 2, 64) + "^" + explain,
	}
	return mapigate + "?" + c.signOfOneMethod(params), nil
}

func (c *ZhifubaoApiClient) PayByOrderId(ordId string) (res bool, e error) {
	params := publicParams
	params["app_id"] = c.Pid
	params["service"] = "mobile.securitypay.pay"
	params["partner"] = c.Pid
	params["notify_url"] = "url"
	params["out_trade_no"] = ordId
	params["subject"] = "this is a subject"
	params["payment_type"] = "1"
	params["seller_id"] = c.Pid
	params["total_fee"] = "0.01"
	params["body"] = "detail"
	//params["method"] = "alipay.pass.instance.update"
	//params["serial_number"] = ordId
	//params["channel_id"] = ordId

	//params["method"] = "alipay.trade.create"
	//params["out_trade_no"] = ordId
	//params["total_amount"] = "0.01"
	//params["buyer_logon_id"] = "15921622336"
	params["sign"] = c.sign(params)
	form := url.Values{}
	for k, v := range params {
		form.Add(k, v)
	}
	req, err := http.NewRequest("POST", apigate, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Println("a")
		log.Println(err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("b")
		log.Println(err)
		return
	}
	var dat map[string]interface{}
	json.Unmarshal(body, &dat)
	log.Println("c")
	log.Println(dat)
	//log.Println(dat["alipay_trade_query_response"].(map[string]interface{})["sub_msg"])
	//log.Println(dat["alipay_pass_instance_update_response"].(map[string]interface{})["sub_msg"])
	return
}

func (c *ZhifubaoApiClient) QueryOrderByOrderId(ordId string) (res bool, e error) {
	params := publicParams
	params["app_id"] = c.Pid
	params["method"] = "alipay.trade.query"
	params["out_trade_no"] = ordId

	//params["method"] = "alipay.pass.instance.update"
	//params["serial_number"] = ordId
	//params["channel_id"] = ordId

	//params["method"] = "alipay.trade.create"
	//params["out_trade_no"] = ordId
	//params["total_amount"] = "0.01"
	//params["buyer_logon_id"] = "15921622336"
	params["sign"] = c.sign(params)
	form := url.Values{}
	for k, v := range params {
		form.Add(k, v)
	}
	req, err := http.NewRequest("POST", apigate, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Println("a")
		log.Println(err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("b")
		log.Println(err)
		return
	}
	var dat map[string]interface{}
	json.Unmarshal(body, &dat)
	log.Println("c")
	log.Println(dat)
	log.Println(dat["alipay_trade_query_response"].(map[string]interface{})["sub_msg"])
	//log.Println(dat["alipay_pass_instance_update_response"].(map[string]interface{})["sub_msg"])
	return
}
func (c *ZhifubaoApiClient) VerifyNotifyCallback(params url.Values) (res bool, e error) {
	pp := map[string]string{}
	for k, v := range params {
		if value, exist := v[0]; exist && k != "sign" && k != "sign_type" {
			pp[k] = value
		}
	}
	keys := []string{}
	for k, _ := range pp {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	requestStr := []string{}
	for _, k := range keys {
		requestStr = append(requestStr, k+"="+pp[k])
	}
	sign, exist := params["sign"][0]
	if !exist {
		return
	} else {
		return VerifyZhifubaoRes(strings.Join(requestStr, "&"), sign)
	}
}

func (c *ZhifubaoApiClient) QueryOrderByTradeId(tradeId string) (res bool, e error) {
	return
}

//func main() {
//	client := CreateZhifubaoClient("your pid", "/Users/james/Dropbox/HAVE/zhifubao/rsa_private_key.pem")
//}
