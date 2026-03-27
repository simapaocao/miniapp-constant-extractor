require("@babel/runtime/helpers/Arrayincludes");

var e = s(require("./hook/useInitPage")), i = require("./utils/message"), n = require("./store/index"), o = require("./api/index"), l = require("./utils/trialVersion"), r = s(require("./utils/updateManager")), a = require("./sensor/index"), t = require("./sensor/service");

function s(e) {
    return e && e.__esModule ? e : {
        default: e
    };
}

(0, e.default)(), (0, r.default)(), App({
    globalData: {
        isFirstOnShow: !0,
        isGptUser: !1,
        trialUserId: "",
        isGptTrialUser: !1,
        channel: ""
    },
    checkIsTrialUser: function() {
        var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "";
        e ? (this.globalData.isGptTrialUser = !0, this.globalData.trialUserId = e, (0, l.changeToTrialVersion)(e)) : (0, 
        l.checkVersionCatchIsTrial)() && (0, l.getTrialUserId)() ? (this.globalData.isGptTrialUser = !0, 
        this.globalData.trialUserId = (0, l.getTrialUserId)()) : (this.globalData.isGptTrialUser = (0, 
        l.getTrialUserId)(), this.globalData.trialUserId = "");
    },
    exitAndClearTrialVersion: function() {
        (0, l.clearTrialVersion)(), this.checkIsTrialUser("");
    },
    login: function(e) {
        var l = this, r = this.globalData.trialUserId;
        (0, o.userLoginByWechatCodeApi)({
            trialUserId: r
        }).then(function(i) {
            (0, n.changeToken)(i), setTimeout(function() {
                return (null == e ? void 0 : e.onSuccess) && (null == e ? void 0 : e.onSuccess());
            }, 100);
        }).catch(function(o) {
            if ((0, n.changeToken)(""), null == o || !o.errorKey) return console.error(o), console.error("可能出现代码逻辑错误，请检查上一条错误信息");
            "self.login.trial.noPermission" === o.errorKey && (l.exitAndClearTrialVersion(), 
            l.login(), setTimeout(function() {
                return (null == e ? void 0 : e.onFaild) && (null == e ? void 0 : e.onFaild());
            }, 100), (0, i.showWarning)(null == o ? void 0 : o.msg)), "self.login.fail" === o.errorKey ? setTimeout(function() {
                return (null == e ? void 0 : e.onFaild) && (null == e ? void 0 : e.onFaild());
            }, 100) : "wx.login.fail" === o.errorKey && ((0, i.showWarning)("正在获取用户信息"), setTimeout(function() {
                return l.login(e);
            }, 3e3));
        });
    },
    saveApplyFormConfigData: function(e) {
        console.log("保存已经生成的申请表单参数", e), wx.setStorageSync("applyFormDataConfig", e);
    },
    getApplyFormConfigData: function(e) {
        var i, n, o, l = wx.getAccountInfoSync().miniProgram.appId || "wx0ca88461eee34318", r = (null === (i = e.query) || void 0 === i ? void 0 : i.gdt_vid) || "-1", a = "-1", t = wx.getStorageSync("channel");
        null !== (n = e.query) && void 0 !== n && n.weixinadinfo && (a = null === (o = e.query) || void 0 === o ? void 0 : o.weixinadinfo.split(".")[0]);
        var s = {
            appId: l,
            unionid: "",
            clickId: r,
            actionId: a,
            channel: t
        };
        this.saveApplyFormConfigData(s);
    },
    onShow: function(e) {
        var i, n, o, l;
        (console.log("onShow"), console.log(e), this.globalData.isFirstOnShow ? (this.globalData.isFirstOnShow = !1, 
        this.initUserLogin(e)) : [ 1047, 1048, 1049, 1011, 1012, 1013 ].includes(e.scene) && this.initUserLogin(e), 
        null !== (i = e.query) && void 0 !== i && i.gdt_vid && (this.globalData.channel = "WEIXINAD", 
        wx.setStorageSync("channel", "WEIXINAD")), null !== (n = e.query) && void 0 !== n && n.channel) ? (this.globalData.channel = null === (o = e.query) || void 0 === o ? void 0 : o.channel, 
        wx.setStorageSync("channel", null === (l = e.query) || void 0 === l ? void 0 : l.channel)) : this.globalData.channel = wx.getStorageSync("channel");
    },
    initUserLogin: function(e) {
        var i;
        this.checkIsTrialUser(null === (i = e.query) || void 0 === i ? void 0 : i.scene), 
        this.login();
    },
    onLaunch: function(e) {
        var i;
        console.log("onLaunch参数"), console.log(e), this.getApplyFormConfigData(e), (0, a.initSensor)(), 
        (0, t.getOnLunchMsgList)(null === (i = e.query) || void 0 === i ? void 0 : i.channel).then(function(e) {
            e ? (0, a.uploadDataOnLaunch)(e) : console.log("没有拿到需要上报的文字");
        });
    }
});