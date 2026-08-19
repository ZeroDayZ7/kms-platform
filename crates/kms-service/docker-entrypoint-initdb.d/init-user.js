// docker-entrypoint-initdb.d/init-user.js

const appUser = process.env.MONGO_APP_USER;
const appPwd = process.env.MONGO_APP_PASSWORD;
const appDb = process.env.MONGO_APP_DATABASE;

db = db.getSiblingDB(appDb);

db.createUser({
  user: appUser,
  pwd: appPwd,
  roles: [
    { role: "readWrite", db: appDb },
    { role: "dbAdmin", db: appDb },
  ],
});
