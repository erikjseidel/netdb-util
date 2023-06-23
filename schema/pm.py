from marshmallow import Schema, fields, validate, INCLUDE, ValidationError, post_load

POLICY_TYPES = {
        'import' : 'import-policy',
        'export' : 'export-policy',
        'both'   : 'import-export-policy',
        }

POLICY_FAMILIES = {
        'ipv4' : 4,
        'ipv6' : 6,
        'both' : 0,
        }

class PolicySchema(Schema):
    name    = fields.String(required=True, validate=validate.Regexp("^[A-Za-z0-9-]+$"))
    type    = fields.String(required=True, validate=validate.OneOf( list(POLICY_TYPES.keys()) ))
    weight  = fields.Integer(validate = validate.Range(min=1, max=10001))
    family  = fields.String(required=True, validate=validate.OneOf( list(POLICY_FAMILIES.keys()) ))
    comment = fields.String()

    @post_load
    def make_policy(self, data, **kwargs):
        return {
                'name'           : data['name'],
                'slug'           : data['name'].lower(),
                'display'        : data['name'],
                'type'           : POLICY_TYPES[ data['type'] ],
                'address_family' : POLICY_FAMILIES[ data['family'] ],
                'weight'         : data.get('weight') or 1000,
                'comments'       : data.get('comment') or "",
                }


class AsnSchema(Schema):
    asn     = fields.Integer(required=True)
    name    = fields.String(required=True)
    comment = fields.String()

    ipv4_prefix_limit = fields.Integer(validate = validate.Range(min=1, max=10000000))
    ipv6_prefix_limit = fields.Integer(validate = validate.Range(min=1, max=1000000))

    @post_load
    def make_asn(self, data, **kwargs):
        out = {
                'asn'      : data['asn'],
                'name'     : data['name'],
                'comments' : data.get('comment') or "",
                }

        if n := data.get('ipv6_prefix_limit'):
            out['ipv6_max_prefixes'] = n

        if n := data.get('ipv4_prefix_limit'):
            out['ipv4_max_prefixes'] = n

        return out


class DirectSessionSchema(Schema):
    local_ip  = fields.IP()
    remote_ip = fields.IP(required=True)
    password  = fields.String()
    ttl       = fields.Integer(validate = validate.Range(1, 256))
    comment   = fields.String()

    @post_load
    def make_session(self, data, **kwargs):
        out  =  {
                'ip_address' : remote_ip,
                }

        if local_ip := data.get('local_ip'):
            out['local_ip_address'] = local_ip

        if password := data.get('password'):
            out['password'] = password

        if ttl := data.get('ttl'):
            out['ttl'] = ttl

        if comment := data.get('comment'):
            out['comments'] = comment

        return out
