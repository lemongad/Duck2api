package bogdanfinn

import (
	"aurora/httpclient"
	"io"
	"net/http"
	"math/rand"
	"time"
	"crypto/tls"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/EDDYCJY/fake-useragent"
)

type TlsClient struct {
	Client    tls_client.HttpClient
	ReqBefore handler
}

type handler func(r *fhttp.Request) error

func NewStdClient() *TlsClient {
	rand.Seed(time.Now().UnixNano())
	
	// 随机化超时时间
	timeout := rand.Intn(300) + 300
	
	// 随机选择客户端配置文件
	profileList := []tls_client.ClientProfile{
		profiles.Chrome_105,
		profiles.Chrome_106,
		profiles.Firefox_102,
		profiles.Safari_15_6_1,
		profiles.Opera_90,
		profiles.Okhttp4Android13,
	}
	randomProfile := profileList[rand.Intn(len(profileList))]
	
	// 初始化 fake-useragent
	ua := useragent.New()

	// 根据选择的配置文件生成相应的 UA
	var randomUA string
	switch randomProfile {
	case profiles.Chrome_105, profiles.Chrome_106:
		randomUA = ua.Chrome()
	case profiles.Firefox_102:
		randomUA = ua.Firefox()
	case profiles.Safari_15_6_1:
		randomUA = ua.Safari()
	case profiles.Opera_90:
		randomUA = ua.Opera()
	case profiles.Okhttp4Android13:
		randomUA = ua.Android()
	default:
		randomUA = ua.Random()
	}

	// 随机化 TLS 版本
	tlsVersions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	randomTLSVersion := tlsVersions[rand.Intn(len(tlsVersions))]

	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithTimeoutSeconds(uint(timeout)),
		tls_client.WithClientProfile(randomProfile),
		tls_client.WithHeader("User-Agent", randomUA),
		tls_client.WithTLSVersion(randomTLSVersion),
	}...)

	stdClient := &TlsClient{Client: client}
	return stdClient
}

func convertResponse(resp *fhttp.Response) *http.Response {
	response := &http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           http.Header(resp.Header),
		Body:             resp.Body,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          http.Header(resp.Trailer),
	}
	return response
}

func (t *TlsClient) handleHeaders(req *fhttp.Request, headers httpclient.AuroraHeaders) {
	if headers == nil {
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func (t *TlsClient) handleCookies(req *fhttp.Request, cookies []*http.Cookie) {
	if cookies == nil {
		return
	}
	for _, c := range cookies {
		req.AddCookie(&fhttp.Cookie{
			Name:       c.Name,
			Value:      c.Value,
			Path:       c.Path,
			Domain:     c.Domain,
			Expires:    c.Expires,
			RawExpires: c.RawExpires,
			MaxAge:     c.MaxAge,
			Secure:     c.Secure,
			HttpOnly:   c.HttpOnly,
			SameSite:   fhttp.SameSite(c.SameSite),
			Raw:        c.Raw,
			Unparsed:   c.Unparsed,
		})
	}
}

func (t *TlsClient) Request(method httpclient.HttpMethod, url string, headers httpclient.AuroraHeaders, cookies []*http.Cookie, body io.Reader) (*http.Response, error) {
	req, err := fhttp.NewRequest(string(method), url, body)
	if err != nil {
		return nil, err
	}
	t.handleHeaders(req, headers)
	t.handleCookies(req, cookies)
	if t.ReqBefore != nil {
		if err := t.ReqBefore(req); err != nil {
			return nil, err
		}
	}
	do, err := t.Client.Do(req)
	if err != nil {
		return nil, err
	}
	return convertResponse(do), nil
}

func (t *TlsClient) SetProxy(url string) error {
	return t.Client.SetProxy(url)
}
