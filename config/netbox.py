from .secrets import _NETBOX_TOKEN

NETBOX_BASE = 'http://localhost:8096'

NETBOX_HEADERS = {
            'Content-Type'  : 'application/json',
            'Authorization' : 'Token ' + _NETBOX_TOKEN,
            }        

NETBOX_SOURCE = {
        'name'    :  'netbox-test',
        'weight'  :  150,
        }

DEVICE_GQL = """query {
  device_list {
    id
    status
    name
    last_updated
    site {
      id
      name
      status
      region {
        name
      }
      name
      asns {
        asn
      }
      custom_fields
    }
    device_role {
      id
      name
      custom_fields
    }
    custom_fields
    loopbacks: interfaces(type: "dummy") {
      id
      name
      ip_addresses {
        id
        address
        tags {
          name
        }
      }
    }
    wan_ports: interfaces(tag: "wan_port") {
      name
      l2vpn_terminations {
        l2vpn {
          name
          slug
        }
      }
      link_peers {
        __typename
        ... on CircuitTerminationType {
          circuit {
            provider {
              name
              slug
            }
          }
        }
      }
    }
  }
}"""

IFACE_GQL = """query {
  interface_list(device: "%s") {
    id
    name
    type
    description
    mtu
    custom_fields
    untagged_vlan {
      vid
    }
    lag {
      name
      id
    }
    tags {
      name
    }
    last_updated
    ip_addresses {
      address
      dns_name
      tags {
        name
      }
    }
    parent {
      ip_addresses {
        address
        tags {
          name
        }
      }
    }
    virtual_link {
      custom_fields
      interface_a {
        id
        type
        parent {
          id
          ip_addresses {
            address
            tags {
              name
            }
          }
        }
      }
      interface_b {
        id
        type
        parent {
          id
          ip_addresses {
            address
            tags {
              name
            }
          }
        }
      }
    }
  }
  config_context_list {
    id
    name
    last_updated
    tags {
      name
    }
    data
  }
}"""

NETBOX_NETDB = [
        'l2gre',
        'gre',
        'dummy',
        ]

NETBOX_ETHERNET = [
        'virtual',
        'veth',
        '100base-fx',
        '100base-lfx',
        '100base-tx',
        '100base-t1',
        '1000base-t',
        '1000base-x-gbic',
        '1000base-x-sfp',
        '2.5gbase-t',
        '5gbase-t',
        '10gbase-t',
        '10gbase-cx4',
        '10gbase-x-sfpp',
        '10gbase-x-xfp',
        '10gbase-x-xenpak',
        '10gbase-x-x2',
        '25gbase-x-sfp28',
        '50gbase-x-sfp56',
        '40gbase-x-qsfpp',
        '50gbase-x-sfp28',
        '100gbase-x-cfp',
        '100gbase-x-cfp2',
        '100gbase-x-cfp4',
        '100gbase-x-cpak',
        '100gbase-x-qsfp28',
        '200gbase-x-cfp2',
        '200gbase-x-qsfp56',
        '400gbase-x-qsfpdd',
        '400gbase-x-osfp',
        '800gbase-x-qsfpdd',
        '800gbase-x-osfp',
        '1000base-kx',
        '10gbase-kr',
        '10gbase-kx4',
        '25gbase-kr',
        '40gbase-kr4',
        '50gbase-kr',
        '100gbase-kp4',
        '100gbase-kr2',
        '100gbase-kr4',
        ]
