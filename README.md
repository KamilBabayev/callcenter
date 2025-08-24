callcenter


```
go get -u -d github.com/golang-migrate/migrate/v4


go build -tags 'postgres' -o migrate github.com/golang-migrate/migrate/v4/cmd/migrate
```

```

sudo mv migrate  /usr/local/bin/


```


```
~/git/callcenter$ migrate -path migrations -database "postgresql://callcenter:password@127.0.0.1:5432/callcenterdb?sslmode=disable" up

1/u create_tables (63.637312ms)


```

