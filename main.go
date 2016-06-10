package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"time"
	//	"reflect"
)

//Get list of server certificates
//Get list of ELBs with SSL listeners
//Prioritize certificates which are attached to ELBs
//Start notification process to DataDog 45 days out
//Set notification to info @ 45 days
//Set notification to warning @ 30 days
//Set notification to High @ 20 days
//Set notification to Urgent @ 10 days, repeat once daily
//Set notification to emergency @ 5 days and raise hell

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
}

func listCerts() []*iam.ServerCertificateMetadata {
	fmt.Println("Listing Certs")
	svc := iam.New(session.New())
	params := &iam.ListServerCertificatesInput{}
	resp, error := svc.ListServerCertificates(params)

	if error != nil {
		fmt.Println("there was an error", error.Error())
	}
	return resp.ServerCertificateMetadataList
}
func listElbs() []*elb.LoadBalancerDescription {
	var elbList []*elb.LoadBalancerDescription
	fmt.Println("enumerating ELBs across regions")
	params := &elb.DescribeLoadBalancersInput{}
	for _, region := range AwsRegions {
		svc := elb.New(session.New(&aws.Config{Region: aws.String(region)}))
		fmt.Println("enumerating:", region)
		resp, error := svc.DescribeLoadBalancers(params)
		if error != nil {
			fmt.Println("there was an error", error.Error())
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
				matechedElb := ELB{Name: *elb.DNSName, CertId: *elb_listener.Listener.SSLCertificateId}
				ELBsWithSSl = append(ELBsWithSSl, matechedElb)
			}

		}
	}
	return ELBsWithSSl
}
func existsInStringArray(stringArray []string, stringToCheck string) bool {
	var exists bool
	for _, string := range stringArray {
		if string == stringToCheck {
			exists = true
		} else {
			exists = false
		}
	}
	return exists
}
func dedupStringArray(stringArray []string) []string {
	var DedupedArray []string
	for _, string := range stringArray {
		if existsInStringArray(stringArray, string) {
			continue
		} else {
			DedupedArray = append(DedupedArray, string)
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
func checkExpiration(CertDetailsList []CertDetails) []CertDetails {
	Out45 := float64(45)
	Out30 := float64(30)
	Out20 := float64(20)
	Out10 := float64(10)
	Out5 := float64(5)
	Outnow := float64(1)
	for index, certDetail := range CertDetailsList {
		expiresInDays := certDetail.ExpirationDate.Sub(time.Now()).Hours() / 24
		switch {
		case expiresInDays <= Outnow:
			CertDetailsList[index].ExpirationStatus = "EXPIRED"
		case expiresInDays <= Out5:
			CertDetailsList[index].ExpirationStatus = "OUT5"
		case expiresInDays <= Out10:
			CertDetailsList[index].ExpirationStatus = "OUT10"
		case expiresInDays <= Out20:
			CertDetailsList[index].ExpirationStatus = "OUT20"
		case expiresInDays <= Out30:
			CertDetailsList[index].ExpirationStatus = "OUT30"
		case expiresInDays <= Out45:
			CertDetailsList[index].ExpirationStatus = "OUT45"
		default:
			CertDetailsList[index].ExpirationStatus = "GTG"
		}
	}
	return CertDetailsList
}

func main() {
	certs := listCerts() // global reach all certs are part of this response
	elb := listElbs()    // Regional, must call per region
	matching := listELBsWithSSL(elb)
	//fmt.Println(matching)
	//fmt.Println(certs)
	groupedCerts := groupELBsWithCerts(&matching, certs)
	results, _ := json.Marshal(checkExpiration(groupedCerts))
	fmt.Println(string(results))
	fmt.Println("done")
}
