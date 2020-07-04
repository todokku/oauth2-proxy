package requests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bitly/go-simplejson"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Builder suite", func() {
	var b Builder
	getBuilder := func() Builder { return b }

	baseHeaders := http.Header{
		"Accept-Encoding": []string{"gzip"},
		"User-Agent":      []string{"Go-http-client/1.1"},
	}

	BeforeEach(func() {
		// Most tests will request the server address
		b = New(serverAddr + "/json/path")
	})

	Context("with a basic request", func() {
		assertSuccessfulRequest(getBuilder, testHTTPRequest{
			Method:     "GET",
			Header:     baseHeaders,
			Body:       []byte{},
			RequestURI: "/json/path",
		})
	})

	Context("with a context", func() {
		var ctx context.Context
		var cancel context.CancelFunc

		BeforeEach(func() {
			ctx, cancel = context.WithCancel(context.Background())
			b = b.WithContext(ctx)
		})

		AfterEach(func() {
			cancel()
		})

		assertSuccessfulRequest(getBuilder, testHTTPRequest{
			Method:     "GET",
			Header:     baseHeaders,
			Body:       []byte{},
			RequestURI: "/json/path",
		})

		Context("if the context is cancelled", func() {
			BeforeEach(func() {
				cancel()
			})

			assertRequestError(getBuilder, "context canceled")
		})
	})

	Context("with a body", func() {
		const body = "{\"some\": \"body\"}"
		header := baseHeaders.Clone()
		header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

		BeforeEach(func() {
			buf := bytes.NewBuffer([]byte(body))
			b = b.WithBody(buf)
		})

		assertSuccessfulRequest(getBuilder, testHTTPRequest{
			Method:     "GET",
			Header:     header,
			Body:       []byte(body),
			RequestURI: "/json/path",
		})
	})

	Context("with a method", func() {
		Context("POST with a body", func() {
			const body = "{\"some\": \"body\"}"
			header := baseHeaders.Clone()
			header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

			BeforeEach(func() {
				buf := bytes.NewBuffer([]byte(body))
				b = b.WithMethod("POST").WithBody(buf)
			})

			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "POST",
				Header:     header,
				Body:       []byte(body),
				RequestURI: "/json/path",
			})
		})

		Context("POST without a body", func() {
			header := baseHeaders.Clone()
			header.Set("Content-Length", "0")

			BeforeEach(func() {
				b = b.WithMethod("POST")
			})

			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "POST",
				Header:     header,
				Body:       []byte{},
				RequestURI: "/json/path",
			})
		})

		Context("OPTIONS", func() {
			BeforeEach(func() {
				b = b.WithMethod("OPTIONS")
			})

			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "OPTIONS",
				Header:     baseHeaders,
				Body:       []byte{},
				RequestURI: "/json/path",
			})
		})

		Context("INVALID-\\t-METHOD", func() {
			BeforeEach(func() {
				b = b.WithMethod("INVALID-\t-METHOD")
			})

			assertRequestError(getBuilder, "error creating request: net/http: invalid method \"INVALID-\\t-METHOD\"")
		})
	})

	Context("with headers", func() {
		Context("setting a header", func() {
			header := baseHeaders.Clone()
			header.Set("header", "value")

			BeforeEach(func() {
				b = b.SetHeader("header", "value")
			})

			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "GET",
				Header:     header,
				Body:       []byte{},
				RequestURI: "/json/path",
			})

			Context("then replacing the headers", func() {
				replacementHeaders := http.Header{
					"Accept-Encoding": []string{"*"},
					"User-Agent":      []string{"test-agent"},
					"Foo":             []string{"bar, baz"},
				}

				BeforeEach(func() {
					b = b.WithHeader(replacementHeaders)
				})

				assertSuccessfulRequest(getBuilder, testHTTPRequest{
					Method:     "GET",
					Header:     replacementHeaders,
					Body:       []byte{},
					RequestURI: "/json/path",
				})
			})
		})

		Context("replacing the header", func() {
			replacementHeaders := http.Header{
				"Accept-Encoding": []string{"*"},
				"User-Agent":      []string{"test-agent"},
				"Foo":             []string{"bar, baz"},
			}

			BeforeEach(func() {
				b = b.WithHeader(replacementHeaders)
			})

			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "GET",
				Header:     replacementHeaders,
				Body:       []byte{},
				RequestURI: "/json/path",
			})

			Context("then setting a header", func() {
				header := replacementHeaders.Clone()
				header.Set("User-Agent", "different-agent")

				BeforeEach(func() {
					b = b.SetHeader("User-Agent", "different-agent")
				})

				assertSuccessfulRequest(getBuilder, testHTTPRequest{
					Method:     "GET",
					Header:     header,
					Body:       []byte{},
					RequestURI: "/json/path",
				})
			})
		})
	})

	Context("if the request has been completed and then modified", func() {
		BeforeEach(func() {
			_, err := b.Do()
			Expect(err).ToNot(HaveOccurred())

			b.WithMethod("POST")
		})

		Context("should not redo the request", func() {
			assertSuccessfulRequest(getBuilder, testHTTPRequest{
				Method:     "GET",
				Header:     baseHeaders,
				Body:       []byte{},
				RequestURI: "/json/path",
			})
		})
	})

	Context("when the requested page is not found", func() {
		BeforeEach(func() {
			b = New(serverAddr + "/not-found")
		})

		assertJSONError(getBuilder, "404 page not found")
	})

	Context("when the requested page is not valid JSON", func() {
		BeforeEach(func() {
			b = New(serverAddr + "/string/path")
		})

		assertJSONError(getBuilder, "invalid character 'O' looking for beginning of value")
	})
})

func assertSuccessfulRequest(builder func() Builder, expectedRequest testHTTPRequest) {
	Context("Do", func() {
		var resp *http.Response

		BeforeEach(func() {
			var err error
			resp, err = builder().Do()
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns a successful status", func() {
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})

		It("made the expected request", func() {
			body, err := ioutil.ReadAll(resp.Body)
			Expect(err).ToNot(HaveOccurred())
			resp.Body.Close()

			actualRequest := testHTTPRequest{}
			Expect(json.Unmarshal(body, &actualRequest)).To(Succeed())

			Expect(actualRequest).To(Equal(expectedRequest))
		})
	})

	Context("Into", func() {
		var actualRequest testHTTPRequest

		BeforeEach(func() {
			Expect(builder().Into(&actualRequest)).To(Succeed())
		})

		It("made the expected request", func() {
			Expect(actualRequest).To(Equal(expectedRequest))
		})
	})

	Context("JSON", func() {
		var response *simplejson.Json

		BeforeEach(func() {
			var err error
			response, err = builder().JSON()
			Expect(err).ToNot(HaveOccurred())
		})

		It("made the expected reqest", func() {
			header := http.Header{}
			for key, value := range response.Get("Header").MustMap() {
				vs, ok := value.([]interface{})
				Expect(ok).To(BeTrue())
				svs := []string{}
				for _, v := range vs {
					sv, ok := v.(string)
					Expect(ok).To(BeTrue())
					svs = append(svs, sv)
				}
				header[key] = svs
			}

			// Other json unmarhsallers base64 decode byte slices automatically
			body, err := base64.StdEncoding.DecodeString(response.Get("Body").MustString())
			Expect(err).ToNot(HaveOccurred())

			actualRequest := testHTTPRequest{
				Method:     response.Get("Method").MustString(),
				Header:     header,
				Body:       body,
				RequestURI: response.Get("RequestURI").MustString(),
			}

			Expect(actualRequest).To(Equal(expectedRequest))
		})
	})
}

func assertRequestError(builder func() Builder, errorMessage string) {
	Context("Do", func() {
		It("returns an error", func() {
			resp, err := builder().Do()
			Expect(err).To(MatchError(ContainSubstring(errorMessage)))
			Expect(resp).To(BeNil())
		})
	})

	Context("Into", func() {
		It("returns an error", func() {
			var actualRequest testHTTPRequest
			err := builder().Into(&actualRequest)
			Expect(err).To(MatchError(ContainSubstring(errorMessage)))

			// Should be empty
			Expect(actualRequest).To(Equal(testHTTPRequest{}))
		})
	})

	Context("JSON", func() {
		It("returns an error", func() {
			resp, err := builder().JSON()
			Expect(err).To(MatchError(ContainSubstring(errorMessage)))
			Expect(resp).To(BeNil())
		})
	})
}

func assertJSONError(builder func() Builder, errorMessage string) {
	Context("Do", func() {
		It("does not return an error", func() {
			resp, err := builder().Do()
			Expect(err).To(BeNil())
			Expect(resp).ToNot(BeNil())
		})
	})

	Context("Into", func() {
		It("returns an error", func() {
			var actualRequest testHTTPRequest
			err := builder().Into(&actualRequest)
			Expect(err).To(MatchError(ContainSubstring(errorMessage)))

			// Should be empty
			Expect(actualRequest).To(Equal(testHTTPRequest{}))
		})
	})

	Context("JSON", func() {
		It("returns an error", func() {
			resp, err := builder().JSON()
			Expect(err).To(MatchError(ContainSubstring(errorMessage)))
			Expect(resp).To(BeNil())
		})
	})
}
