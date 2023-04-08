
ADDR_FILTER  = { 
        "address": { "$exists": 1 } 
        }

DNS_FILTER   = { "$where": """
            function () {
                for (var index in this.address)
                    if (this.address[index].meta.dns)
                        return this;
            } """
        }

ADDR_VIEW    = { "address": 1 }

ADDR_PROJECT = { 'filter': ADDR_FILTER, 'projection': ADDR_VIEW }

DNS_PROJECT  = { 'filter': DNS_FILTER, 'projection': ADDR_VIEW }
