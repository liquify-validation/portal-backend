from API import create_flask_app
from DB import db

app = create_flask_app(db)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0',use_reloader=False)