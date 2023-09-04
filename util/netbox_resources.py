
NETBOX_ETHERNET = [
        'VIRTUAL',
        'VETH',
        'A_100BASE_TX',
        'A_1000BASE_T',
        'A_2_5GBASE_T',
        'A_5GBASE_T',
        'A_10GBASE_T',
        ]

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
        slug
      }
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
  interface_list {
    device {
      name
    }
    id
    name
    type
    description
    mtu
    mac_address
    enabled
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
      id
      address
      dns_name
      last_updated
      tags {
        name
      }
    }
    parent {
      name
      ip_addresses {
        address
        tags {
          name
        }
      }
    }
    virtual_link {
      custom_fields
      status
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

ONE_IFACE_GQL = """query {
  interface_list(device: "%s", name: "%s") {
    device {
      name
    }
    id
    name
    type
    description
    mtu
    mac_address
    enabled
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
      id
      address
      dns_name
      last_updated
      tags {
        name
      }
    }
    parent {
      name
      ip_addresses {
        address
        tags {
          name
        }
      }
    }
    virtual_link {
      custom_fields
      status
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

IGP_GQL = """query {
  devices: device_list {
    name
    device_role {
      id
    }
    active: interfaces(tag: "igp") {
      name   
    }
    passive: interfaces(tag: "igp_passive") {
      name    
    }
    custom_fields
  }
  contexts: config_context_list(tag: "igp") {
    id
    name
    last_updated
    data
    roles {
      id
    }
  }
}"""

EBGP_GQL = """query {
  devices: device_list {
    name
    config_context
    ebgp_interfaces: interfaces(tag: "ebgp") {
      id
      tags {
        name
      }
      virtual_link {
        status
        interface_a {
          id
          name
          ip_addresses {
            tags {
              name
            }
            address
            family {
              label
              value
            }
          }
          device {
            site {
              asns {
                asn
              }
            }
          }
        }
        interface_b {
          id
          name
          ip_addresses {
            tags {
              name
            }
            address
            family {
              label
              value
            }
          }
          device {
            site {
              asns {
                asn
              }
            }
          }
        }
      }
    }
  }
}"""
