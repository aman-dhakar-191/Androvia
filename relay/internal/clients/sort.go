package clients

import "sort"

func sortClients(cs []Client) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].CreatedAt.Equal(cs[j].CreatedAt) {
			return cs[i].ID < cs[j].ID
		}
		return cs[i].CreatedAt.Before(cs[j].CreatedAt)
	})
}

func sortGrants(gs []Grant) {
	sort.Slice(gs, func(i, j int) bool { return gs[i].DeviceID < gs[j].DeviceID })
}
