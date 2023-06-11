from .secrets import PM_TOKEN, PM_BASE, PM_URL_BASE

PM_HEADERS = {
            'Content-Type'  : 'application/json',
            'Authorization' : 'Token ' + PM_TOKEN,
            }        

PM_SOURCE = {
        'name'    :  'peering_manager',
        'weight'  :  125,
        }
