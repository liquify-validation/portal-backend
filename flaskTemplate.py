template = {
    "swagger": "2.0",
    "info": {
        "title": "Liquify Portal API",
        "description": "Backend for frontend gateway portal",
        "specs_route": "/docs",
        "contact": {
            "responsibleOrganization": "Liquify LTD",
            "responsibleDeveloper": "Liquify LTD",
            "email": "contact@liquify.io",
            "url": "https://www.liquify.io",
        },
        "version": "1.0"
    },
    "specs_route": "/docs",
    "schemes": [
        "http"
    ],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            'description': "Type in the *'Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token"
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

swagger_config = {
    "headers": [
    ],
    "specs": [
        {
            "endpoint": 'specifications',
            "route": '/specifications.json',
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    "specs_route": "/docs",
}