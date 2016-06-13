package main

import (
	//"encoding/json"
	"fmt"
	"time"
	"log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/zorkian/go-datadog-api"
	"os"
	"encoding/json"
)


var AwsRegions = []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "sa-east-1"}

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
	fmt.Println("Processing IAM Certs")
	svc := iam.New(session.New())
	params := &iam.ListServerCertificatesInput{}
	resp, err := svc.ListServerCertificates(params)

	if err != nil {
		fmt.Println("there was an error listing certificates from AWS", err.Error())
		log.Fatal(err.Error())
	}
	return resp.ServerCertificateMetadataList
}

func listElbs() []*elb.LoadBalancerDescription {
	var elbList []*elb.LoadBalancerDescription
	fmt.Println("Processing ELBs")
	params := &elb.DescribeLoadBalancersInput{}
	for _, region := range AwsRegions {
		svc := elb.New(session.New(&aws.Config{Region: aws.String(region)}))
		fmt.Println("enumerating ELBs in:", region)
		resp, err := svc.DescribeLoadBalancers(params)
		if err != nil {
			fmt.Println("there was an error listing ELBS in", region, err.Error())
			log.Fatal(err.Error())
		}
		for _, elb := range resp.LoadBalancerDescriptions {
			elbList = append(elbList, elb)
		}
	}
	return elbList
}

func listELBsWithSSL(elb_list []*elb.LoadBalancerDescription) []ELB {
	var ELBsWithSSl []ELB
	for _, elb := range elb_list {
		//		fmt.Println(*elb.DNSName)
		for _, elb_listener := range elb.ListenerDescriptions {
			if *elb_listener.Listener.Protocol == "HTTPS" || *elb_listener.Listener.Protocol == "SSL" {
				//				fmt.Println("bingo")
				matchedElb := ELB{Name: *elb.DNSName, CertId: *elb_listener.Listener.SSLCertificateId}
				ELBsWithSSl = append(ELBsWithSSl, matchedElb)
			}

		}
	}
	return ELBsWithSSl
}

func existsInStringArray(stringArray []string, stringToCheck string) bool {
	var exists bool
	for _, str := range stringArray {
		if str == stringToCheck {
			exists = true
		} else {
			exists = false
		}
	}
	return exists
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
	fmt.Println(description)
	event := datadog.Event{Title: "Certificate expiration notice",
		Text: description,
		Priority: "normal",
		AlertType: certInfo.ExpirationStatus,
		Aggregation: certInfo.Arn,
	        SourceType: "certificate_checker"}

	ddClient := datadog.NewClient(os.Getenv("API_KEY"),os.Getenv("APP_KEY"))
	res, err := ddClient.PostEvent(&event)
	if err != nil {
		log.Println("Could not post event to DD", err.Error())
	}
	log.Printf("Posted event for %s successfully. Event ID: %x", certInfo.Arn,res.Id)

}

func main() {
	certs := listCerts() // global reach all certs are part of this response
	elb := listElbs()    // Regional, must call per region
	matching := listELBsWithSSL(elb)
	//fmt.Println(matching)
	//fmt.Println(certs)
	groupedCerts := groupELBsWithCerts(&matching, certs)
	checkExpirationAndTriggerAlert(groupedCerts)
	//log.Println(string(results))
	log.Println("Completed", time.Now())
}
