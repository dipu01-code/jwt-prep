const test = require("node:test");
const assert = require("node:assert");
const jwt = require("jsonwebtoken");
const { app, prisma } = require("./index");


const testEmail = "test-" + Date.now() + "@example.com";
const testPassword = "secret1";

let server;
let baseUrl;
let savedToken;


async function sendRequest(method, path, body, token) {
  const options = {
    method: method,
    headers: { "Content-Type": "application/json" },
  };
  if (body) {
    options.body = JSON.stringify(body);
  }
  if (token) {
    options.headers.Authorization = "Bearer " + token;
  }

  const response = await fetch(baseUrl + path, options);
  const data = await response.json();
  return { status: response.status, body: data };
}




test.before(async function () {
  await new Promise(function (resolve) {
    server = app.listen(0, resolve);
  });
  baseUrl = "http://localhost:" + server.address().port;
});


test.after(async function () {
  try {
    await prisma.user.deleteMany({ where: { email: testEmail } });
    await prisma.$disconnect();
  } catch (error) {
    console.error("Cleanup failed:", error);
  }
  server.close();
});


test("signup: password shorter than 6 characters gives 400", async function () {
  const result = await sendRequest("POST", "/signup", { email: testEmail, password: "12345" });
  assert.equal(result.status, 400);
});

test("signup: missing email gives 400", async function () {
  const result = await sendRequest("POST", "/signup", { password: testPassword });
  assert.equal(result.status, 400);
});

test("signup: valid details give 201, a clean email and a token", async function () {

  const messyEmail = "  " + testEmail.toUpperCase() + " ";
  const result = await sendRequest("POST", "/signup", { email: messyEmail, password: testPassword });

  assert.equal(result.status, 201);
  assert.equal(result.body.user.email, testEmail);
  assert.equal(result.body.user.password, undefined);


  const payload = jwt.decode(result.body.token);
  assert.equal(payload.id, result.body.user.id);
  assert.equal(payload.email, testEmail);
  assert.ok(payload.jti);
  assert.equal(payload.exp - payload.iat, 3600);
});

test("signup: same email again gives 409", async function () {
  const result = await sendRequest("POST", "/signup", { email: testEmail, password: testPassword });
  assert.equal(result.status, 409);
});



test("login: missing password gives 400", async function () {
  const result = await sendRequest("POST", "/login", { email: testEmail });
  assert.equal(result.status, 400);
});

test("login: wrong password and unknown email give the same 401", async function () {
  const wrongPassword = await sendRequest("POST", "/login", {
    email: testEmail,
    password: "wrong-password",
  });
  const unknownEmail = await sendRequest("POST", "/login", {
    email: "nobody@example.com",
    password: testPassword,
  });

  assert.equal(wrongPassword.status, 401);
  assert.equal(unknownEmail.status, 401);
  assert.equal(wrongPassword.body.error, unknownEmail.body.error);
});

test("login: correct details give 200 and a token", async function () {
  const result = await sendRequest("POST", "/login", { email: testEmail, password: testPassword });

  assert.equal(result.status, 200);
  assert.equal(result.body.user.email, testEmail);
  assert.equal(result.body.user.password, undefined);
  assert.ok(result.body.token);

  savedToken = result.body.token;
});



test("/me and /dashboard: no token gives 401", async function () {
  const me = await sendRequest("GET", "/me");
  const dashboard = await sendRequest("GET", "/dashboard");
  assert.equal(me.status, 401);
  assert.equal(dashboard.status, 401);
});

test("/me and /dashboard: a fake token gives 401", async function () {
  const me = await sendRequest("GET", "/me", null, "not-a-real-token");
  const dashboard = await sendRequest("GET", "/dashboard", null, "not-a-real-token");
  assert.equal(me.status, 401);
  assert.equal(dashboard.status, 401);
});

test("/me and /dashboard: an expired token gives 401", async function () {

  const expiredToken = jwt.sign({ id: 1, email: testEmail }, process.env.JWTSECRET, {
    expiresIn: -1,
  });
  const me = await sendRequest("GET", "/me", null, expiredToken);
  const dashboard = await sendRequest("GET", "/dashboard", null, expiredToken);
  assert.equal(me.status, 401);
  assert.equal(dashboard.status, 401);
});

test("/me: valid token gives 200 and the profile without the password", async function () {
  const result = await sendRequest("GET", "/me", null, savedToken);

  assert.equal(result.status, 200);
  assert.equal(result.body.user.email, testEmail);
  assert.ok(result.body.user.id);
  assert.ok(result.body.user.createdAt);
  assert.equal(result.body.user.password, undefined);
});

test("/dashboard: valid token gives 200 and a welcome message", async function () {
  const result = await sendRequest("GET", "/dashboard", null, savedToken);

  assert.equal(result.status, 200);

  assert.equal(result.body.message, "Welcome, " + testEmail + "!");
});

test("/me and /dashboard: token of a user that does not exist gives 404", async function () {

  const tokenForMissingUser = jwt.sign({ id: 2147483647, email: testEmail }, process.env.JWTSECRET, {
    expiresIn: "1h",
  });
  const me = await sendRequest("GET", "/me", null, tokenForMissingUser);
  const dashboard = await sendRequest("GET", "/dashboard", null, tokenForMissingUser);
  assert.equal(me.status, 404);
  assert.equal(dashboard.status, 404);
});
