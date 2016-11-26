package main

import (
	"fmt"
	"time"
	"log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"encoding/json"
	"github.com/zorkian/go-datadog-api"
	"os"
)



type ELB struct {
	Name   string
	CertId string
}

type CertDetails struct {
	Arn              string
	ExpirationDate   time.Time
	Name             string
	AttachedELBs     []ELB
	ExpirationStatus string
	Daysleft         float64
}

func listCerts() []*iam.ServerCertificateMetadata {
	svc := iam.New(session.New())
	params := &iam.ListServerCertificatesInput{}
	resp, err := svc.ListServerCertificates(params)

	if err != nil {
	}
	return resp.ServerCertificateMetadataList
}

	params := &elb.DescribeLoadBalancersInput{}
	for _, region := range AwsRegions {
		svc := elb.New(session.New(&aws.Config{Region: aws.String(region)}))
		resp, err := svc.DescribeLoadBalancers(params)
		if err != nil {
		}
		for _, elb := range resp.LoadBalancerDescriptions {
			elbList = append(elbList, elb)
		}
	}
}

	for _, elb := range elb_list {
		for _, elb_listener := range elb.ListenerDescriptions {
			if *elb_listener.Listener.Protocol == "HTTPS" || *elb_listener.Listener.Protocol == "SSL" {
				matchedElb := ELB{Name: *elb.DNSName, CertId: *elb_listener.Listener.SSLCertificateId}
				ELBsWithSSl = append(ELBsWithSSl, matchedElb)
			}

		}
	}
}

func existsInStringArray(stringArray []string, stringToCheck string) bool {
	for _, str := range stringArray {
		if str == stringToCheck {
		}
	}
}

func dedupStringArray(stringArray []string) []string {
	var DedupedArray []string
	for _, str := range stringArray {
		if existsInStringArray(stringArray, str) {
			continue
		} else {
			DedupedArray = append(DedupedArray, str)
		}

	}
	return DedupedArray
}

func extractUniqueELBCerts(elb_list *[]ELB) []string {
	var ELBCerts []string
	for _, elb := range *elb_list {
		ELBCerts = append(ELBCerts, elb.CertId)
	}
	dedupedCertsList := dedupStringArray(ELBCerts)
	return dedupedCertsList
}

func selectCertByArn(cert_list []*iam.ServerCertificateMetadata, cert_arn string) iam.ServerCertificateMetadata {
	Certificate := iam.ServerCertificateMetadata{}
	for _, cert_detail := range cert_list {
		if *cert_detail.Arn == cert_arn {
			Certificate = *cert_detail
			break
		}
	}
	return Certificate
}

func groupELBsWithCerts(elb_list *[]ELB, cert_list []*iam.ServerCertificateMetadata) []CertDetails {
	var CertDetailsList []CertDetails
	usedCerts := extractUniqueELBCerts(elb_list)
	for _, cert_arn := range usedCerts {
		var elbCollection []ELB
		for _, elb := range *elb_list {
			if elb.CertId == cert_arn {
				elbCollection = append(elbCollection, elb)
			}
		}
		cert_details := selectCertByArn(cert_list, cert_arn)
		CertDetailsList = append(CertDetailsList, CertDetails{Arn: cert_arn, ExpirationDate: *cert_details.Expiration, Name: *cert_details.ServerCertificateName, AttachedELBs: elbCollection})
	}
	return CertDetailsList
}

func checkExpirationAndTriggerAlert(CertDetailsList []CertDetails) []CertDetails {
	Out45 := float64(45)
	Out30 := float64(30)
	Out20 := float64(20)
	Out10 := float64(10)
	Out5 := float64(5)
	Outnow := float64(1)
	for index, certDetail := range CertDetailsList {
		expiresInDays := certDetail.ExpirationDate.Sub(time.Now()).Hours() / 24
		CertDetailsList[index].Daysleft = expiresInDays
		switch {
		case expiresInDays <= Outnow:
			CertDetailsList[index].ExpirationStatus = "error"
		case expiresInDays <= Out5:
			CertDetailsList[index].ExpirationStatus = "error"
		case expiresInDays <= Out10:
			CertDetailsList[index].ExpirationStatus = "warning"
		case expiresInDays <= Out20:
			CertDetailsList[index].ExpirationStatus = "warning"
		case expiresInDays <= Out30:
			CertDetailsList[index].ExpirationStatus = "info"
		case expiresInDays <= Out45:
			CertDetailsList[index].ExpirationStatus = "info"
		default:
			CertDetailsList[index].ExpirationStatus = "GTG"
		}
		if CertDetailsList[index].ExpirationStatus != "GTG" {
			postAlertEventDD(CertDetailsList[index])
		}
	}
	return CertDetailsList
}

func postAlertEventDD(certInfo CertDetails) {
	certJson, err := json.MarshalIndent(certInfo, "", "  ")
	if err != nil {
		log.Println("Could not marshall cert info to json", err.Error())
	}
	description := fmt.Sprintf("Certificate: %v  expiring in %0.f days.\n There are currently %v ELBs using this certificate. \n Details: %v  \n",
		certInfo.Arn, certInfo.Daysleft, len(certInfo.AttachedELBs), string(certJson))
	var tags = []string{accountTag}
	if DEBUG {
		fmt.Println(description)
		return
	}
	event := datadog.Event{Title: "Certificate expiration notice",
		Text: description,
		Priority: "normal",
		AlertType: certInfo.ExpirationStatus,
		Aggregation: certInfo.Arn,
		SourceType: "certificate_checker",
		Tags: tags }

	ddClient := datadog.NewClient(os.Getenv("DD_API_KEY"), os.Getenv("DD_APP_KEY"))
	res, err := ddClient.PostEvent(&event)
	if err != nil {
		log.Println("Could not post event to DD", err.Error())
	}
	log.Printf("Posted event for %s successfully. Event ID: %x", certInfo.Arn, res.Id)

}

func main() {
	certs := listCerts()
	elb := listElbs()
	matching := listELBsWithSSL(elb)
	groupedCerts := groupELBsWithCerts(&matching, certs)
	checkExpirationAndTriggerAlert(groupedCerts)
	log.Println("Completed", time.Now())
}
