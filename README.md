## CARSI IdP 支持企业微信认证的插件

## 原理说明

Shibboleth IdP 本身提供了一种支持与外部认证系统对接的 [External](https://wiki.shibboleth.net/confluence/display/IDP30/ExternalAuthnConfiguration) 机制。[Unicon](https://github.com/Unicon)/[shib-cas-authn](https://github.com/Unicon/shib-cas-authn) 又提供了一个第三方的插件使得External可以支持将CAS统一认证系统作为认证源与IdP进行对接，是上述Shibboleth 的 对接External认证源的一个非常好的实现版本。

由于CAS协议与OAuth 2.0协议在很多认证步骤上都比较接近，北京大学计算中心CARSI团队的王博、赖清楠、陈萍、张扬几位老师，在此基础上进行了改造，使得其可以支持符合OAuth协议的认证源。华东师范大学冯骐老师在此基础上写了一份对接原理（[Shibboleth-IdP 的 OAuth2 对接方案详解](https://www.jianshu.com/p/0d50a6d6a653?utm_campaign=haruki&utm_content=note&utm_medium=reader_share&utm_source=weixin_timeline&from=timeline)），详细对比了CAS与OAuth 2.0的差异，并进一步优化了插件功能， 最终CARSI联盟提供的3.4.7版本IdP与OAuth认证源对接的方案 [对接校园网认证系统](https://wiki.carsi.edu.cn/pages/viewpage.action?pageId=6266126) 中的对接OAuth认证源部分，则使用了此版本。

由于微校的通讯录功能提供了OAuth协议的对接入口，因此我们可以进一步改造这个插件，以使其适应微校提供的API。本插件适配了微校的提供的API，基于当前的微校提供的官方开发文档，读取微校通讯录中的用户信息，对CARSI要求释放的用户属性进行了传递，并精简了代码。开发时测试的IdP为4.1.2版本。

认证时：如果是在微信App中使用，则微校基于自身的上下文直接就可以认证通过了；如果是基于微信App以外的环境（如PC或手机浏览器）中使用，则打开微校通讯录提供的登录页面（二维码，使用微信App扫码登录）。

使用说明
---------------------------------------------------------------

#### 自行编译

```
gradle build -x test 
```

#### IdP配置

请参照CARSI的wiki（待补充url）配置IdP使用External的认证方式。特别注意以下配置：

1. 在`idp.properties`中添加对接企业微信需要用到的属性：

```
# Weixiao properties
shibcarsi.serverName = https://{IDP_DNS}
shibcarsi.weixiao.appkey = [1234567890123456]
shibcarsi.weixiao.appsecret = [abcdefghijklmnopqrstuvwxyz123456]
shibcarsi.weixiao.ocode = [1234567890]
shibcarsi.weixiao.oauth2LoginUrl = https://open.wecard.qq.com/connect/oauth/pc-authorize?app_key=${shibcarsi.weixiao.appkey}&response_type=code&ocode=${shibcarsi.weixiao.ocode}&scope=snsapi_userinfo&state=STATE&connect=curLogin
shibcarsi.weixiao.oauth2LoginUrlH5 = https://open.wecard.qq.com/connect/oauth/authorize?app_key=${shibcarsi.weixiao.appkey}&response_type=code&ocode=${shibcarsi.weixiao.ocode}&scope=snsapi_userinfo&state=STATE
shibcarsi.weixiao.oauth2TokenUrl = https://open.wecard.qq.com/connect/oauth2/token
shibcarsi.weixiao.oauth2ResourceUrl = https://open.wecard.qq.com/connect/oauth/get-user-info
shibcarsi.weixiao.oauth2clientid = ${shibcarsi.weixiao.appkey}
shibcarsi.weixiao.oauth2clientsecret = ${shibcarsi.weixiao.appsecret}
```

其中`serverName`中的{IDP_DNS}替换为IdP域名；`appkey`为应用的Appkey，`appsecret`为应用的AppSecret，`ocode`为学校的code（这3个属性需要对照微校的管理员后台填写）。

2. 需要将所有build出来的jar包放置在`/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/`路径中
3. 然后重新build IdP：`/opt/shibboleth-idp/bin/build.sh`
4. 最后重启IdP的web容器

改进建议
-------------------------------------------------------------

如果您有好的建议，欢迎联系carsi@pku.edu.cn，本项目同时欢迎您加入维护。