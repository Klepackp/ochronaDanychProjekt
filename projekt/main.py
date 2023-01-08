from website import create_app

app = create_app()

if __name__=='__main__':
    context = ('domain.crt', 'domain.key')
    app.run(host="0.0.0.0", debug=False, ssl_context=context)

