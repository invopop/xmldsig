package xmldsig

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// List of free TSA servers: https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
const (
	TimestampFreeTSA = "https://freetsa.org/tsr"
)

// Timestamp contains ...
type Timestamp struct {
	CanonicalizationMethod *AlgorithmMethod `xml:"ds:CanonicalizationMethod"`
	EncapsulatedTimeStamp  string           `xml:"xades:EncapsulatedTimeStamp"`
}

// TimestampSignatureValue contains ...
type TimestampSignatureValue struct {
	XMLName   xml.Name
	Namespace string `xml:"xmlns:ds,attr"`
	ID        string `xml:"Id,attr"`
	Value     string `xml:",chardata"`
}

func buildTimestampValue(signatureValue *Value, serviceURL string) (*Timestamp, error) {
	data, err := generateTimestampHash(signatureValue)
	if err != nil {
		return nil, err
	}

	timestamp, err := requestTimestamp(serviceURL, data)
	if err != nil {
		return nil, err
	}

	return &Timestamp{
		CanonicalizationMethod: &AlgorithmMethod{
			Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
		},
		EncapsulatedTimeStamp: timestamp,
	}, nil
}

func generateTimestampHash(val *Value) (*bytes.Buffer, error) {
	xmlData := &TimestampSignatureValue{
		XMLName: xml.Name{
			Local: "ds:SignatureValue",
		},
		Namespace: "http://www.w3.org/2000/09/xmldsig#",
		ID:        val.ID,
		Value:     val.Value,
	}
	data, err := xml.Marshal(xmlData)
	if err != nil {
		return nil, fmt.Errorf("marshalling xml: %w", err)
	}

	hasher := crypto.SHA1.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	// TODO: Figure out where these strings come from!!!
	prefix, _ := hex.DecodeString("302c0201013021300906052b0e03021a05000414")
	suffix, _ := hex.DecodeString("0201000101ff")

	buf := bytes.NewBuffer(prefix)
	buf.Write(hash)
	buf.Write(suffix)

	return buf, nil
}

func requestTimestamp(serviceURL string, data io.Reader) (string, error) {
	request, err := http.NewRequest("POST", serviceURL, data)
	if err != nil {
		return "", fmt.Errorf("timestamp request: %w", err)
	}

	request.Header.Set("Content-Type", "application/timestamp-query")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("creating http client: %w", err)
	}
	defer func() {
		err := response.Body.Close()
		if err != nil {
			fmt.Println(err.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("timestamp response error: %v", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}
	if !bytes.Equal(body[6:9], []byte{2, 1, 0}) {
		return "", errors.New("timestamp response error: invalid response")
	}

	return base64.StdEncoding.EncodeToString(body[9:]), nil
}
