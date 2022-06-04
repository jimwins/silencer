package filter

import (
	"context"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"log"
	"net"
)

type cf_filter struct {
	api     *cloudflare.API
	account string
	list_id string
}

func NewCloudflare(account string, list_id string, auth_email string, auth_key string) *cf_filter {
	api, err := cloudflare.New(auth_key, auth_email)
	// alternatively, you can use a scoped API token
	// api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	return &cf_filter{api, account, list_id}
}

func (b cf_filter) Block(ip net.IP) {
	// Most API calls require a Context
	ctx := context.Background()

	b.api.CreateIPListItemAsync(ctx, b.account, b.list_id, ip.String(), "Blocked by silencer")
}

func (b cf_filter) Unblock(ip net.IP) {
	ctx := context.Background()

	list, _ := b.api.ListIPListItems(ctx, b.account, b.list_id)

	for _, item := range list {
		check := net.ParseIP(item.IP).To4()
		if check == nil {
			fmt.Printf("invalid IPv4 address: %q", item.IP)
			continue
		}
		if check.String() == ip.String() {
			b.api.DeleteIPListItemsAsync(ctx, b.account, b.list_id, cloudflare.IPListItemDeleteRequest{[]cloudflare.IPListItemDeleteItemRequest{cloudflare.IPListItemDeleteItemRequest{item.ID}}})
		}
	}
}

func parseIPList(incoming []cloudflare.IPListItem) (list []net.IP) {
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

func (b cf_filter) List() []net.IP {
	// Most API calls require a Context
	ctx := context.Background()

	list, _ := b.api.ListIPListItems(ctx, b.account, b.list_id)

	return parseIPList(list)
}
