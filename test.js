// Runs against the real database in DATABASE_URL; cleans up the user it creates.
const test = require("node:test");
const assert = require("node:assert");
const jwt = require("jsonwebtoken");
const { app, prisma } = require("./index");

const email = `test-${Date.now()}@example.com`;
let base, server, token;

const call = async (method, path, body, auth) => {
  const res = await fetch(base + path, {
    method,
    headers: { "Content-Type": "application/json", ...(auth && { Authorization: auth }) },
    body: body && JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
};

test.before(() => new Promise((r) => {
  server = app.listen(0, () => { base = `http://localhost:${server.address().port}`; r(); });
}));
test.after(async () => {
  await prisma.user.deleteMany({ where: { email } });
  await prisma.$disconnect();
  server.close();
});

test("signup", async () => {
  assert.equal((await call("POST", "/signup", { email, password: "12345" })).status, 400);
  assert.equal((await call("POST", "/signup", { password: "123456" })).status, 400);

  const res = await call("POST", "/signup", { email: `  ${email.toUpperCase()} `, password: "secret1" });
  assert.equal(res.status, 201);
  assert.equal(res.body.user.email, email);
  assert.equal(res.body.user.password, undefined);
  const payload = jwt.decode(res.body.token);
  assert.equal(payload.id, res.body.user.id);
  assert.equal(payload.email, email);
  assert.ok(payload.jti);
  assert.equal(payload.exp - payload.iat, 3600);

  assert.equal((await call("POST", "/signup", { email, password: "secret1" })).status, 409);
});

test("login", async () => {
  assert.equal((await call("POST", "/login", { email })).status, 400);
  const wrong = await call("POST", "/login", { email, password: "nope-nope" });
  const unknown = await call("POST", "/login", { email: "nobody@example.com", password: "secret1" });
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.deepEqual(wrong.body, unknown.body);

  const ok = await call("POST", "/login", { email: ` ${email.toUpperCase()}`, password: "secret1" });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.user.password, undefined);
  token = ok.body.token;
});

test("protected routes", async () => {
  for (const path of ["/me", "/dashboard"]) {
    assert.equal((await call("GET", path)).status, 401);
    assert.equal((await call("GET", path, null, "Bearer garbage")).status, 401);
    const expired = jwt.sign({ id: 1, email }, process.env.JWTSECRET, { expiresIn: -1 });
    assert.equal((await call("GET", path, null, `Bearer ${expired}`)).status, 401);
  }

  const me = await call("GET", "/me", null, `Bearer ${token}`);
  assert.equal(me.status, 200);
  assert.deepEqual(Object.keys(me.body.user).sort(), ["createdAt", "email", "id", "name"]);

  const dash = await call("GET", "/dashboard", null, `Bearer ${token}`);
  assert.equal(dash.status, 200);
  assert.equal(dash.body.message, `Welcome, ${email}!`);

  const ghost = jwt.sign({ id: 2147483647, email }, process.env.JWTSECRET, { expiresIn: "1h" });
  assert.equal((await call("GET", "/me", null, `Bearer ${ghost}`)).status, 404);
  assert.equal((await call("GET", "/dashboard", null, `Bearer ${ghost}`)).status, 404);
});
