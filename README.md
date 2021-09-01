instalar dependências
```
npm install
```

criar o arquivo .env
```
cp .env.example .env
```

criar o banco
```
node ace migration:run
```

criar o usuário admin
```
node ace db:seed
``
