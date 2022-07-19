const fetch = require("node-fetch");
const encrypt = require("./encrypt-stripped.js");

module.exports = class SMSManager {
  constructor(host, user, password) {
    this.host = host;
    this.user = user;
    this.passbase64 = Buffer.from(password).toString('base64');
  }

  async login() {
    let resp = await fetch(
      `${this.host}/cgi/getParm`,
      {
        method: 'POST',
        headers: {
          'Referer': this.host
        }
      }
    );
    const vars = await resp.text();
    const ee = vars.match(/var ee="(.*?)";/)[1];
    const nn = vars.match(/var nn="(.*?)";/)[1];
    const userRSA = encrypt.rsa.encrypt('admin', nn, ee);
    const passRSA = encrypt.rsa.encrypt(this.passbase64, nn, ee);
    resp = await fetch(
      `${this.host}/cgi/login?UserName=${userRSA}&Passwd=${passRSA}&Action=1&LoginStatus=0`,
      {
        method: 'POST',
        headers: {
          'Connection': 'keep-alive',
          'DNT': '1',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0',
          'Accept': '*/*',
          'Referer': this.host,
          'Accept-Language': 'en-US,en;q=0.9',
          'Cookie': 'loginErrorShow=1',
          'Pragma': 'no-cache',
          'Cache-Control': 'no-cache'
        },
        body: '',
        compress: true
      });
    this.jSessionID = resp.headers.raw()['set-cookie'].toString().match(/JSESSIONID=(.*?);/)[1];
    resp = await fetch(
      this.host,
      {
        method: 'GET',
        headers: {
          'Connection': 'keep-alive',
          'DNT': '1',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0',
          'Accept': '*/*',
          'Referer': this.host,
          'Accept-Language': 'en-US,en;q=0.9',
          'Cookie': `loginErrorShow=1; JSESSIONID=${this.jSessionID}`,
          'Upgrade-Insecure-Requests': '1',
          'Cache-Control': 'max-age=0'
        },
        compress: true
      });
      this.tokenID = (await resp.text()).match(/var token="(.*?)";/)[1];
      console.log("[MR400] Logged in successfully.");
  }

  async mr400API(cgi, payload) {
    const resp = await fetch(
      `${this.host}/cgi?${cgi}`,
      {
        method: 'POST',
        headers: {
          'Connection': 'keep-alive',
          'DNT': '1',
          'TokenID': this.tokenID,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0',
          'Content-Type': 'text/plain',
          'Accept': '*/*',
          'Referer': this.host,
          'Accept-Language': 'en-US,en;q=0.9',
          'Cookie': `loginErrorShow=1; JSESSIONID=${this.jSessionID}`
        },
        body: payload,
        compress: true
      });
    return await resp.text();
  }
}
