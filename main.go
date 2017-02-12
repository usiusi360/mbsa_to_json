package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/tealeg/xlsx"
	//"io"
	"io/ioutil"
	"os"
	//"runtime"
	_ "reflect"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type MbsaXML struct {
	Check []struct {
		GroupName string `xml:"GroupName,attr"`
		Name      string `xml:"Name,attr"`
		Advice    string
		Detail    struct {
			UpdateData []struct {
				Title           string
				ID              string `xml:"ID,attr"`
				BulletinID      string `xml:"BulletinID,attr"`
				RestartRequired string `xml:"RestartRequired,attr"`
				IsInstalled     string `xml:"IsInstalled,attr"`
				KBID            string `xml:"KBID,attr"`
				Severity        string `xml:"Severity,attr"`
				References      struct {
					BulletinURL    string
					InformationURL string
					DownloadURL    string
				}
				OtherIDs []struct {
					OtherID string
				}
			}
		}
	}
}

type SecXlsx []struct {
	BulletinId  string //column 1
	ComponentKB string //column 7
	CVEs        string //column 13
}

type ScanResult struct {
	ScannedAt time.Time

	Lang       string
	ServerName string // TOML Section key
	Family     string
	Release    string
	Container  Container
	Platform   Platform

	// Scanned Vulns via SSH + CPE Vulns
	ScannedCves []VulnInfo

	KnownCves   []CveInfo
	UnknownCves []CveInfo
	IgnoredCves []CveInfo

	Packages PackageInfoList

	Optional [][]interface{}
}

type Container struct {
	ContainerID string
	Name        string
}

type Platform struct {
	Name       string // aws or azure or gcp or other...
	InstanceID string
}

type VulnInfo struct {
	CveID            string
	Packages         PackageInfoList
	DistroAdvisories []DistroAdvisory // for Aamazon, RHEL, FreeBSD
	CpeNames         []string
}

type DistroAdvisory struct {
	AdvisoryID string
	Severity   string
	Issued     time.Time
	Updated    time.Time
}

type CveInfo struct {
	CveDetail cve.CveDetail
	VulnInfo
}

const filePath = `C:\Users\ushida2590\Desktop\MBSA\`

func main() {

	//TODO OSバージョン判定

	myXML, err := loadXMLfile("mbsareport.xml")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Println(myXML)

	fmt.Println(myXML.Check)

	// mySlice, err := loadXlsxfile("BulletinSearch.xlsx")
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	//fmt.Println(mySlice[0][0][1])
	// for i := 0; i < len(mySlice[0]); i++ {
	// 	fmt.Println(mySlice[0][i][1] + " " + mySlice[0][i][7] + " " + mySlice[0][i][13])
	// }

}

func loadXlsxfile(fileName string) ([][][]string, error) {
	mySlice, err := xlsx.FileToSlice(filePath + fileName)
	if err != nil {
		return nil, fmt.Errorf("xlsx load error")
	}
	return mySlice, nil
}

func loadXMLfile(fileName string) (MbsaXML, error) {
	var mbsaXML MbsaXML

	xmlData, err := ioutil.ReadFile(filePath + fileName)
	if err != nil {
		return mbsaXML, fmt.Errorf("file not found")
	}

	xmlDataU16, err := decodeUTF16(xmlData)
	if err != nil {
		return mbsaXML, fmt.Errorf("decode error")
	}

	nr := strings.NewReader(xmlDataU16)
	decoder := xml.NewDecoder(nr)
	err = decoder.Decode(&mbsaXML)
	if err != nil {
		panic(err)
	}

	return mbsaXML, nil
}

func decodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("Must have even length byte slice")
	}

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)
	lb := len(b)

	for i := 2; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	return ret.String(), nil
}
