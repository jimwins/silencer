package filter

import (
	"fmt"
	"github.com/fastly/go-fastly/v7/fastly"
	"log"
	"net"
)

type fastly_filter struct {
	api     *fastly.Client
	api_key string
	service_id string
	acl_id string
}

func NewFastly(api_key string, service_id string, acl_id string) *fastly_filter {
	api, err := fastly.NewClient(api_key)
	if err != nil {
		log.Fatal(err)
	}
	return &fastly_filter{api, api_key, service_id, acl_id}
}

func (b fastly_filter) Block(ip net.IP) {
	comment := "Blocked by silencer"
	ips := ip.String()

	_, err := b.api.CreateACLEntry(&fastly.CreateACLEntryInput{
		ServiceID: b.service_id,
		ACLID: b.acl_id,
		Comment: &comment,
		IP: &ips,
	})

	if err != nil {
		log.Fatal(err)
	}
}

func (b fastly_filter) Unblock(ip net.IP) {
	list, _ := b.api.ListACLEntries(&fastly.ListACLEntriesInput{
		ServiceID: b.service_id,
		ACLID: b.acl_id,
	})

	for _, item := range list {
		check := net.ParseIP(item.IP).To4()
		if check == nil {
			fmt.Printf("invalid IPv4 address: %q", item.IP)
			continue
		}
		if check.String() == ip.String() {
			err := b.api.DeleteACLEntry(&fastly.DeleteACLEntryInput{
				ServiceID: item.ServiceID,
				ACLID: item.ACLID,
				ID: item.ID,
			})
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func parseFastlyIPList(incoming []*fastly.ACLEntry) (list []net.IP) {
	for _, item := range incoming {
		ip := net.ParseIP(item.IP).To4()
		if ip == nil {
			fmt.Printf("invalid IPv4 address: %q", item.IP)
			continue
		}
		list = append(list, ip)
	}
	return
}

func (b fastly_filter) List() []net.IP {
	list, err := b.api.ListACLEntries(&fastly.ListACLEntriesInput{
		ServiceID: b.service_id,
		ACLID: b.acl_id,
	})

	if err != nil {
		log.Fatal(err)
	}

	return parseFastlyIPList(list)
}
