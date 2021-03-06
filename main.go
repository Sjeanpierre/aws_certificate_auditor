package main

//Required ENV VARS
//DD_API_KEY
//DD_APP_KEY
//AWS_ACCOUNT_NAME

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
	"errors"
	"github.com/aws/aws-lambda-go/lambda"
)

var awsRegions = []string{
	"us-east-1",
	"us-west-1",
	"us-west-2",
	"eu-west-1",
	"eu-central-1",
	"sa-east-1",
}

var debug = false

type awsELB struct {
	Name   string
	CertID string
}

type certDetails struct {
	Arn              string
	ExpirationDate   time.Time
	Name             string
	AttachedELBs     []awsELB
	ExpirationStatus string
	Daysleft         float64
}

func listCerts() []*iam.ServerCertificateMetadata {
	log.Println("Processing IAM Certs")
	session,err := session.NewSession()
	if err != nil {
		log.Fatalf("Could not create new AWS session, check credentials")
	}
	svc := iam.New(session)
	params := &iam.ListServerCertificatesInput{}
	resp, err := svc.ListServerCertificates(params)

	if err != nil {
		log.Fatal("there was an error listing certificates from AWS", err.Error())
	}
	return resp.ServerCertificateMetadataList
}

func listElbs() (elbList []*elb.LoadBalancerDescription) {
	log.Println("Processing ELBs")
	params := &elb.DescribeLoadBalancersInput{}
	for _, region := range awsRegions {
		svc := elb.New(session.New(&aws.Config{Region: aws.String(region)}))
		log.Println("enumerating ELBs in:", region)
		resp, err := svc.DescribeLoadBalancers(params)
		if err != nil {
			log.Fatal("there was an error listing ELBS in", region, err.Error())
		}
		for _, elb := range resp.LoadBalancerDescriptions {
			elbList = append(elbList, elb)
		}
	}
	return
}

func listELBsWithSSL(elbList []*elb.LoadBalancerDescription) (ELBsWithSSl []awsELB) {
	for _, elb := range elbList {
		for _, elbListener := range elb.ListenerDescriptions {
			if *elbListener.Listener.Protocol == "HTTPS" || *elbListener.Listener.Protocol == "SSL" {
				matchedElb := awsELB{
					Name: *elb.DNSName,
					CertID: *elbListener.Listener.SSLCertificateId,
				}
				ELBsWithSSl = append(ELBsWithSSl, matchedElb)
			}

		}
	}
	return
}

func dedupStringArray(stringArray []string) []string {
	var DedupedArray []string //will hold the final results of the dedup process
	//use hash map to dedup strings based on the fact that it does not allow duplicate keys.
	//also avoids us having to iterate over the whole slice each time for existence checks
	var a = make(map[string]struct{})
	for _, s := range stringArray { //each unique string will only show once in this map
		a[s] = struct{}{}
	}
	for key := range a { //take unique keys and append them to slice, slice only contains uniq values now
		DedupedArray = append(DedupedArray,key)
	}
	return DedupedArray
}

func extractUniqueELBCerts(elbList *[]awsELB) []string {
	var ELBCerts []string
	for _, elb := range *elbList {
		ELBCerts = append(ELBCerts, elb.CertID)
	}
	dedupedCertsList := dedupStringArray(ELBCerts)
	return dedupedCertsList
}

func selectCertByArn(certList []*iam.ServerCertificateMetadata, certArn string) (iam.ServerCertificateMetadata,error) {
	Certificate := iam.ServerCertificateMetadata{}
	for _, certDetail := range certList {
		if *certDetail.Arn == certArn {
			return *certDetail,nil
		}
	}
	return Certificate,errors.New("could not find cert")
}

func groupELBsWithCerts(elbList []awsELB, certList []*iam.ServerCertificateMetadata) []certDetails {
	var CertDetailsList []certDetails
	usedCerts := extractUniqueELBCerts(&elbList)
	for _, certArn := range usedCerts {
		var elbCollection []awsELB
		for _, elb := range elbList {
			if elb.CertID == certArn {
				elbCollection = append(elbCollection, elb)
			}
		}
		Details,err := selectCertByArn(certList, certArn)
		if err != nil {
			continue
		}
		certDetail := certDetails{Arn: certArn,
			ExpirationDate: *Details.Expiration,
			Name: *Details.ServerCertificateName,
			AttachedELBs: elbCollection}
		CertDetailsList = append(CertDetailsList,certDetail)
	}
	return CertDetailsList
}

func checkExpirationAndTriggerAlert(CertDetailsList []certDetails) []certDetails {
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

func postAlertEventDD(certInfo certDetails) {
	certJSON, err := json.MarshalIndent(certInfo, "", "  ")
	if err != nil {
		log.Println("Could not marshall cert info to json", err.Error())
	}
	description := fmt.Sprintf("Certificate: %v  expiring in %0.f day(s).\n There are currently %v ELB(s) using this certificate. \n Details: %+v  \n",
		certInfo.Arn,
		certInfo.Daysleft,
		len(certInfo.AttachedELBs),
		string(certJSON))
	accountTag := fmt.Sprintf("aws_account:%s", os.Getenv("AWS_ACCOUNT_NAME"))
	var tags = []string{accountTag}
	if debug {
		fmt.Println(description)
		return
	}
	event := datadog.Event{
		Title: "Certificate expiration notice",
		Text: description,
		Priority: "normal",
		AlertType: certInfo.ExpirationStatus,
		Aggregation: certInfo.Arn,
		SourceType: "certificate_checker",
		Tags: tags,
	}

	ddClient := datadog.NewClient(os.Getenv("DD_API_KEY"), os.Getenv("DD_APP_KEY"))
	res, err := ddClient.PostEvent(&event)
	if err != nil {
		log.Println("Could not post event to DD", err.Error())
		os.Exit(1)
	}
	log.Printf("Posted event for %s successfully. Event ID: %x", certInfo.Arn, res.Id)

}

func Handler() {
	certs := listCerts()
	elb := listElbs()
	matching := listELBsWithSSL(elb)
	groupedCerts := groupELBsWithCerts(matching, certs)
	checkExpirationAndTriggerAlert(groupedCerts)
	log.Println("Completed", time.Now())
}

func main() {
	lambda.Start(Handler)
}
