### Как запустить: 
  1. git clone https://github.com/kirilldarealcaucasian/auth-service.git
  В config/config.go в MustLoadConfig() указать путь до cоnfig.yaml, в setup.sql лежит sql, необходимый для работы сервиса(нужно добавить одного пользователя в users, чтобы его авторизировать), по поводу невынесения секретов и прочего в .env - не успел, хотел в докере задать env'ы и так все запустить
