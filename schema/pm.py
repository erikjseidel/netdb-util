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

class pmPolicySchema(Schema):
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
