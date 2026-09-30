// 脱敏合成样例：所有凭证均为假造，仅用于验证扫描规则。
var appSecret = "0000000000000000000000000000dead";
var webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=00000000-0000-0000-0000-000000000000";
var accessKeyId = "AKIDFAKEEXAMPLEKEY0000000000000000";
var accessKeySecret = "00000000000000000000000000000000";
var mapKey = "https://apis.map.qq.com/ws/geocoder/v1/?key=00000-00000-00000-00000-00000-00000";
var token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJmYWtlIjp0cnVlfQ.FAKESIGNATUREFAKESIGNATUREFAKE";
var personalId = "110101190001010000";
var mail = "example@example.com";
var privateKey = "-----BEGIN PRIVATE KEY-----\nMIIFAKEFAKEKEYFAKEKEYFAKEKEYFAKEKEY\n-----END PRIVATE KEY-----";
module.exports = { appSecret, webhook, accessKeyId, accessKeySecret, mapKey, token, personalId, mail, privateKey };
