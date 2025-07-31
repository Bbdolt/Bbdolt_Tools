# nuclei_regex检测规则 - 敏感信息泄露检测
nuclei_regex = [
    # {
    #     "Rule": r'["]?zopim[_-]?account[_-]?key["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "Zopim Account Key"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?zhuliang[_-]?gh[_-]?token["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "Zhuliang GitHub Token"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?zensonatypepassword["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "ZenSonatype Password"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?zendesk[_-]?travis[_-]?github["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "Zendesk Travis GitHub"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?yt[_-]?server[_-]?api[_-]?key["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "YouTube Server API Key"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?yt[_-]?partner[_-]?refresh[_-]?token["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "YouTube Partner Refresh Token"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["]?yt[_-]?partner[_-]?client[_-]?secret["]?[^\S\r\n]*[=:][^\S\r\n]*["]?[\w-]+["]?',
    #     "VerboseName": "YouTube Partner Client Secret"
    # }, # 国外服务，国内极少遇到，危害有限
    # {
    #     "Rule": r'["\']?yangshun[_-]?gh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Yangshun GitHub Token"
    # },
    # {
    #     "Rule": r'["\']?yangshun[_-]?gh[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Yangshun GitHub Password"
    # },
    # {
    #     "Rule": r'["\']?www[_-]?googleapis[_-]?com["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Google APIs Key"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT SSH Private Key Base64"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?ssh[_-]?connect["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT SSH Connect"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?report[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT Report API Key"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?prepare[_-]?dir["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT Prepare Directory"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?db[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT Database User"
    # },
    # {
    #     "Rule": r'["\']?wpt[_-]?db[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPT Database Password"
    # },
    # {
    #     "Rule": r'["\']?wporg[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WordPress.org Password"
    # },
    # {
    #     "Rule": r'["\']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WPJM PHPUnit Google Geocode API Key"
    # },
    # {
    #     "Rule": r'["\']?wordpress[_-]?db[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WordPress DB User"
    # },
    # {
    #     "Rule": r'["\']?wordpress[_-]?db[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WordPress DB Password"
    # },
    # {
    #     "Rule": r'["\']?wincert[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Wincert Password"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?test[_-]?server["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Test Server"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?fb[_-]?password[_-]?3["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget FB Password 3"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?fb[_-]?password[_-]?2["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget FB Password 2"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?fb[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget FB Password"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?basic[_-]?password[_-]?5["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Basic Password 5"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?basic[_-]?password[_-]?4["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Basic Password 4"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?basic[_-]?password[_-]?3["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Basic Password 3"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?basic[_-]?password[_-]?2["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Basic Password 2"
    # },
    # {
    #     "Rule": r'["\']?widget[_-]?basic[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Widget Basic Password"
    # },
    # {
    #     "Rule": r'["\']?watson[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Watson Password"
    # },
    # {
    #     "Rule": r'["\']?watson[_-]?device[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Watson Device Password"
    # },
    # {
    #     "Rule": r'["\']?watson[_-]?conversation[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Watson Conversation Password"
    # },
    # {
    #     "Rule": r'["\']?wakatime[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "WakaTime API Key"
    # },
    # {
    #     "Rule": r'["\']?vscetoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "VSCEToken"
    # },
    # {
    #     "Rule": r'["\']?visual[_-]?recognition[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Visual Recognition API Key"
    # },
    # {
    #     "Rule": r'["\']?virustotal[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "VirusTotal API Key"
    # },
    # {
    #     "Rule": r'["\']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "VIP GitHub Deploy Key Pass"
    # },
    # {
    #     "Rule": r'["\']?vip[_-]?github[_-]?deploy[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "VIP GitHub Deploy Key"
    # },
    # {
    #     "Rule": r'["\']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "VIP GitHub Build Repo Deploy Key"
    # },
    # {
    #     "Rule": r'["\']?v[_-]?sfdc[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SFDC Password"
    # },
    # {
    #     "Rule": r'["\']?v[_-]?sfdc[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SFDC Client Secret"
    # },
    # {
    #     "Rule": r'["\']?usertravis["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "User Travis"
    # },
    # {
    #     "Rule": r'["\']?user[_-]?assets[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "User Assets Secret Access Key"
    # },
    # {
    #     "Rule": r'["\']?user[_-]?assets[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "User Assets Access Key ID"
    # },
    # {
    #     "Rule": r'["\']?use[_-]?ssh["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Use SSH"
    # },
    # {
    #     "Rule": r'["\']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "US East 1 ELB Amazon"
    # },
    # {
    #     "Rule": r'["\']?urban[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Urban Secret"
    # },
    # {
    #     "Rule": r'["\']?urban[_-]?master[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Urban Master Secret"
    # },
    # {
    #     "Rule": r'["\']?urban[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Urban Key"
    # },
    # {
    #     "Rule": r'["\']?unity[_-]?serial["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Unity Serial"
    # },
    # {
    #     "Rule": r'["\']?unity[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Unity Password"
    # },
    # {
    #     "Rule": r'["\']?twitteroauthaccesstoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twitter OAuth Access Token"
    # },
    # {
    #     "Rule": r'["\']?twitteroauthaccesssecret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twitter OAuth Access Secret"
    # },
    # {
    #     "Rule": r'["\']?twitter[_-]?consumer[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twitter Consumer Secret"
    # },
    # {
    #     "Rule": r'["\']?twitter[_-]?consumer[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twitter Consumer Key"
    # },
    # {
    #     "Rule": r'["\']?twine[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twine Password"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio Token"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio SID"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?configuration[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio Configuration SID"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio Chat Account API Service"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?api[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio API Secret"
    # },
    # {
    #     "Rule": r'["\']?twilio[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Twilio API Key"
    # },
    # {
    #     "Rule": r'["\']?trex[_-]?okta[_-]?client[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "TRex Okta Client Token"
    # },
    # {
    #     "Rule": r'["\']?trex[_-]?client[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "TRex Client Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?secure[_-]?env[_-]?vars["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis Secure Env Vars"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?pull[_-]?request["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis Pull Request"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?gh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis GitHub Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?e2e[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis E2E Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?com[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis.com Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?branch["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis Branch"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis API Token"
    # },
    # {
    #     "Rule": r'["\']?travis[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Travis Access Token"
    # },
    # {
    #     "Rule": r'["\']?token[_-]?core[_-]?java["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Token Core Java"
    # },
    {
        "Rule": r'(?i)(["\'])(?:thera[_-]?oss[_-]?access[_-]?key)\1\s*[:=]\s*\1([A-Z0-9]{20,40})\1',
        "VerboseName": "Thera OSS Access Key"
    },
    # {
    #     "Rule": r'["\']?tester[_-]?keys[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Tester Keys Password"
    # },
    # {
    #     "Rule": r'["\']?test[_-]?test["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Test Test"
    # },
    # {
    #     "Rule": r'["\']?test[_-]?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Test GitHub Token"
    # },
    # {
    #     "Rule": r'["\']?tesco[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Tesco API Key"
    # },
    # {
    #     "Rule": r'["\']?svn[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SVN Password"
    # },
    # {
    #     "Rule": r'["\']?surge[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Surge Token"
    # },
    # {
    #     "Rule": r'["\']?surge[_-]?login["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Surge Login"
    # },
    # {
    #     "Rule": r'["\']?stripe[_-]?public["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stripe Public"
    # },
    # {
    #     "Rule": r'["\']?stripe[_-]?private["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stripe Private"
    # },
    # {
    #     "Rule": r'["\']?strip[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stripe Secret Key"
    # },
    # {
    #     "Rule": r'["\']?strip[_-]?publishable[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stripe Publishable Key"
    # },
    # {
    #     "Rule": r'["\']?stormpath[_-]?api[_-]?key[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stormpath API Key Secret"
    # },
    # {
    #     "Rule": r'["\']?stormpath[_-]?api[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Stormpath API Key ID"
    # },
    # {
    #     "Rule": r'["\']?starship[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Starship Auth Token"
    # },
    # {
    #     "Rule": r'["\']?starship[_-]?account[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Starship Account SID"
    # },
    # {
    #     "Rule": r'["\']?star[_-]?test[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Star Test Secret Access Key"
    # },
    # {
    #     "Rule": r'["\']?star[_-]?test[_-]?location["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "测试位置信息"
    # },
    {
        "Rule": r'(?i)(["\'])(?:star[_-]?test[_-]?bucket)\1\s*[:=]\s*\1([a-z0-9_-]{3,63})\1',
        "VerboseName": "测试存储桶信息"
    },
    # {
    #     "Rule": r'["\']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "AWS访问密钥ID测试"
    # },
    # {
    #     "Rule": r'["\']?staging[_-]?base[_-]?url[_-]?runscope["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Runscope暂存基础URL"
    # },
    # {
    #     "Rule": r'["\']?ssmtp[_-]?config["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SSMTP配置信息"
    # },
    # {
    #     "Rule": r'["\']?sshpass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SSH密码"
    # },
    # {
    #     "Rule": r'["\']?srcclr[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SourceClear API令牌"
    # },
    # {
    #     "Rule": r'["\']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Square Reader SDK仓库密码"
    # },
    # {
    #     "Rule": r'["\']?sqssecretkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SQS密钥"
    # },
    # {
    #     "Rule": r'["\']?sqsaccesskey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SQS访问密钥"
    # },
    # {
    #     "Rule": r'["\']?spring[_-]?mail[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Spring邮件密码"
    # },
    # {
    #     "Rule": r'["\']?spotify[_-]?api[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Spotify API客户端密钥"
    # },
    # {
    #     "Rule": r'["\']?spotify[_-]?api[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Spotify API访问令牌"
    # },
    # {
    #     "Rule": r'["\']?spaces[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "DO Spaces密钥"
    # },
    # {
    #     "Rule": r'["\']?spaces[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "DO Spaces访问ID"
    # },
    # {
    #     "Rule": r'["\']?soundcloud[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SoundCloud密码"
    # },
    # {
    #     "Rule": r'["\']?soundcloud[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SoundCloud客户端密钥"
    # },
    # {
    #     "Rule": r'["\']?sonatypepassword["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype密码"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?token[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype令牌用户"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?token[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype令牌密码"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype密码"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype通行证"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?nexus[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype Nexus密码"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?gpg[_-]?passphrase["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype GPG口令"
    # },
    # {
    #     "Rule": r'["\']?sonatype[_-]?gpg[_-]?key[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonatype GPG密钥名称"
    # },
    # {
    #     "Rule": r'["\']?sonar[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonar令牌"
    # },
    # {
    #     "Rule": r'["\']?sonar[_-]?project[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonar项目密钥"
    # },
    # {
    #     "Rule": r'["\']?sonar[_-]?organization[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonar组织密钥"
    # },
    # {
    #     "Rule": r'["\']?socrata[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Socrata密码"
    # },
    # {
    #     "Rule": r'["\']?socrata[_-]?app[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Socrata应用令牌"
    # },
    # {
    #     "Rule": r'["\']?snyk[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Snyk令牌"
    # },
    # {
    #     "Rule": r'["\']?snyk[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Snyk API令牌"
    # },
    # {
    #     "Rule": r'["\']?snoowrap[_-]?refresh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Snoowrap刷新令牌"
    # },
    # {
    #     "Rule": r'["\']?snoowrap[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Snoowrap密码"
    # },
    # {
    #     "Rule": r'["\']?snoowrap[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Snoowrap客户端密钥"
    # },
    # {
    #     "Rule": r'["\']?slate[_-]?user[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Slate用户邮箱"
    # },
    # {
    #     "Rule": r'["\']?slash[_-]?developer[_-]?space[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Slash开发者空间密钥"
    # },
    # {
    #     "Rule": r'["\']?slash[_-]?developer[_-]?space["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Slash开发者空间"
    # },
    # {
    #     "Rule": r'["\']?signing[_-]?key[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "签名密钥SID"
    # },
    # {
    #     "Rule": r'["\']?signing[_-]?key[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "签名密钥秘钥"
    # },
    # {
    #     "Rule": r'["\']?signing[_-]?key[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "签名密钥密码"
    # },
    # {
    #     "Rule": r'["\']?signing[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "签名密钥"
    # },
    # {
    #     "Rule": r'["\']?setsecretkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "设置秘钥"
    # },
    # {
    #     "Rule": r'["\']?setdstsecretkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "设置目标秘钥"
    # },
    # {
    #     "Rule": r'["\']?setdstaccesskey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "设置目标访问密钥"
    # },
    # {
    #     "Rule": r'["\']?ses[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SES秘钥"
    # },
    # {
    #     "Rule": r'["\']?ses[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SES访问密钥"
    # },
    # {
    #     "Rule": r'["\']?service[_-]?account[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "服务账户秘钥"
    # },
    # {
    #     "Rule": r'["\']?sentry[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sentry密钥"
    # },
    # {
    #     "Rule": r'["\']?sentry[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sentry秘钥"
    # },
    # {
    #     "Rule": r'["\']?sentry[_-]?endpoint["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sentry端点"
    # },
    # {
    #     "Rule": r'["\']?sentry[_-]?default[_-]?org["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sentry默认组织"
    # },
    # {
    #     "Rule": r'["\']?sentry[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sentry认证令牌"
    # },
    # {
    #     "Rule": r'["\']?sendwithus[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendWithUs密钥"
    # },
    # {
    #     "Rule": r'["\']?sendgrid[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid用户名"
    # },
    # {
    #     "Rule": r'["\']?sendgrid[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid用户"
    # },
    # {
    #     "Rule": r'["\']?sendgrid[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid密码"
    # },
    # {
    #     "Rule": r'["\']?sendgrid[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid密钥"
    # },
    # {
    #     "Rule": r'["\']?sendgrid[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid API密钥"
    # },
    # {
    #     "Rule": r'["\']?sendgrid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SendGrid凭证"
    # },
    # {
    #     "Rule": r'["\']?selion[_-]?selenium[_-]?host["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SeLion Selenium主机"
    # },
    # {
    #     "Rule": r'["\']?selion[_-]?log[_-]?level[_-]?dev["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SeLion开发日志级别"
    # },
    # {
    #     "Rule": r'["\']?segment[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Segment API密钥"
    # },
    # {
    #     "Rule": r'["\']?secretid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥ID"
    # },
    # {
    #     "Rule": r'["\']?secretkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥密钥"
    # },
    # {
    #     "Rule": r'["\']?secretaccesskey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥访问密钥"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?key[_-]?base["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "基础秘钥密钥"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?9["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥9"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?8["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥8"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?7["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥7"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?6["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥6"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?5["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥5"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?4["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥4"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?3["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥3"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?2["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥2"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?11["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥11"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?10["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥10"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?1["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥1"
    # },
    # {
    #     "Rule": r'["\']?secret[_-]?0["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "秘钥0"
    # },
    # {
    #     "Rule": r'["\']?sdr[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SDR令牌"
    # },
    # {
    #     "Rule": r'["\']?scrutinizer[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Scrutinizer令牌"
    # },
    # {
    #     "Rule": r'["\']?sauce[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sauce访问密钥"
    # },
    # {
    #     "Rule": r'["\']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "沙盒AWS秘钥访问密钥"
    # },
    # {
    #     "Rule": r'["\']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "沙盒AWS访问密钥ID"
    # },
    # {
    #     "Rule": r'["\']?sandbox[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "沙盒访问令牌"
    # },
    # {
    #     "Rule": r'["\']?salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Salesforce批量测试安全令牌"
    # },
    # {
    #     "Rule": r'["\']?salesforce[_-]?bulk[_-]?test[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Salesforce批量测试密码"
    # },
    # {
    #     "Rule": r'["\']?sacloud[_-]?api["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SaCloud API"
    # },
    # {
    #     "Rule": r'["\']?sacloud[_-]?access[_-]?token[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SaCloud访问令牌秘钥"
    # },
    # {
    #     "Rule": r'["\']?sacloud[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "SaCloud访问令牌"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?user[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3用户密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?secret[_-]?assets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3资源密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?secret[_-]?app[_-]?logs["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3应用日志密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?key[_-]?assets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3资源访问密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?key[_-]?app[_-]?logs["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3应用日志访问密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3访问密钥"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3外部Amazon连接"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?bucket[_-]?name[_-]?assets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3资源存储桶名称"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?bucket[_-]?name[_-]?app[_-]?logs["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3应用日志存储桶名称"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3访问密钥ID"
    # },
    # {
    #     "Rule": r'["\']?s3[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "S3访问密钥"
    # },
    # {
    #     "Rule": r'["\']?rubygems[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "RubyGems认证令牌"
    # },
    # {
    #     "Rule": r'["\']?rtd[_-]?store[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "RTD存储密码"
    # },
    # {
    #     "Rule": r'["\']?rtd[_-]?key[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "RTD密钥密码"
    # },
    {
    "Rule": r'(?i)(["\'])(?:rtd[_-]?(?:store[_-]?pass|key[_-]?pass))\1\s*[:=]\s*\1([^\s\"\'\\]{8,64})\1',
    "VerboseName": "RTD存储密码/密钥密码"
    },
    {
        "Rule": r'(?i)(["\'])(?:route53[_-]?access[_-]?key[_-]?id)\1\s*[:=]\s*\1([A-Z0-9]{20})\1',
        "VerboseName": "Route53访问密钥ID"
    },
    {
        "Rule": r'["\']?ropsten[_-]?private[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Ropsten以太坊私钥"
    },
    {
        "Rule": r'["\']?rinkeby[_-]?private[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Rinkeby以太坊私钥"
    },
    {
        "Rule": r'["\']?rest[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "REST API密钥"
    },
    {
        "Rule": r'["\']?repotoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "仓库令牌"
    },
    {
        "Rule": r'["\']?reporting[_-]?webdav[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "报告WebDAV URL"
    },
    {
        "Rule": r'["\']?reporting[_-]?webdav[_-]?pwd["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "报告WebDAV密码"
    },
    {
        "Rule": r'["\']?release[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "发布令牌"
    },
    {
        "Rule": r'["\']?release[_-]?gh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub发布令牌"
    },
    {
        "Rule": r'["\']?registry[_-]?secure["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "注册表安全凭证"
    },
    {
        "Rule": r'["\']?registry[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "注册表密码"
    },
    {
        "Rule": r'["\']?refresh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "刷新令牌"
    },
    {
        "Rule": r'["\']?rediscloud[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Redis云URL"
    },
    {
        "Rule": r'["\']?redis[_-]?stunnel[_-]?urls["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Redis隧道URLs"
    },
    {
        "Rule": r'["\']?randrmusicapiaccesstoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "R&R音乐API访问令牌"
    },
    {
        "Rule": r'["\']?rabbitmq[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "RabbitMQ密码"
    },
    {
        "Rule": r'["\']?quip[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Quip令牌"
    },
    {
        "Rule": r'["\']?qiita[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Qiita令牌"
    },
    {
        "Rule": r'["\']?pypi[_-]?passowrd["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PyPI密码"
    },
    {
        "Rule": r'["\']?pushover[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Pushover令牌"
    },
    {
        "Rule": r'["\']?publish[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "发布密钥"
    },
    {
        "Rule": r'["\']?publish[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "发布密钥"
    },
    {
        "Rule": r'["\']?publish[_-]?access["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "发布访问权限"
    },
    {
        "Rule": r'["\']?project[_-]?config["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "项目配置"
    },
    {
        "Rule": r'["\']?prod[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "生产环境密钥"
    },
    {
        "Rule": r'["\']?prod[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "生产环境密码"
    },
    {
        "Rule": r'["\']?prod[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "生产环境访问密钥ID"
    },
    {
        "Rule": r'["\']?private[_-]?signing[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "私有签名密码"
    },
    {
        "Rule": r'["\']?pring[_-]?mail[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Spring邮件用户名"
    },
    {
        "Rule": r'["\']?preferred[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "首选用户名"
    },
    {
        "Rule": r'["\']?prebuild[_-]?auth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "预构建认证"
    },
    {
        "Rule": r'["\']?postgresql[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PostgreSQL密码"
    },
    {
        "Rule": r'["\']?postgresql[_-]?db["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PostgreSQL数据库"
    },
    {
        "Rule": r'["\']?postgres[_-]?env[_-]?postgres[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Postgres环境密码"
    },
    {
        "Rule": r'["\']?postgres[_-]?env[_-]?postgres[_-]?db["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Postgres环境数据库"
    },
    {
        "Rule": r'["\']?plugin[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "插件密码"
    },
    {
        "Rule": r'["\']?plotly[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Plotly API密钥"
    },
    {
        "Rule": r'["\']?places[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Places API密钥"
    },
    {
        "Rule": r'["\']?places[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Places API密钥"
    },
    {
        "Rule": r'["\']?pg[_-]?host["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PostgreSQL主机"
    },
    {
        "Rule": r'["\']?pg[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PostgreSQL数据库"
    },
    {
        "Rule": r'["\']?personal[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "个人秘钥"
    },
    {
        "Rule": r'["\']?personal[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "个人密钥"
    },
    {
        "Rule": r'["\']?percy[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Percy令牌"
    },
    {
        "Rule": r'["\']?percy[_-]?project["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Percy项目"
    },
    {
        "Rule": r'["\']?paypal[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PayPal客户端密钥"
    },
    {
        "Rule": r'["\']?passwordtravis["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Travis密码"
    },
    {
        "Rule": r'["\']?parse[_-]?js[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Parse JS密钥"
    },
    {
        "Rule": r'["\']?pagerduty[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PagerDuty API密钥"
    },
    {
        "Rule": r'["\']?packagecloud[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "PackageCloud令牌"
    },
    # {
    #     "Rule": r'["\']?ossrh[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "OSSRH用户名"
    # },
    # {
    #     "Rule": r'["\']?ossrh[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "OSSRH秘钥"
    # },
    # {
    #     "Rule": r'["\']?ossrh[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "OSSRH密码"
    # },
    # {
    #     "Rule": r'["\']?ossrh[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "OSSRH通行证"
    # },
    # {
    #     "Rule": r'["\']?ossrh[_-]?jira[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "OSSRH JIRA密码"
    # },
    {
        "Rule": r'["\']?os[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "操作系统密码"
    },
    {
        "Rule": r'["\']?os[_-]?auth[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "操作系统认证URL"
    },
    # {
    #     "Rule": r'["\']?org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "组织项目Gradle Sonatype Nexus密码"
    # },
    # {
    #     "Rule": r'["\']?org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "组织Gradle项目Sonatype Nexus密码"
    # },
    {
        "Rule": r'["\']?openwhisk[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OpenWhisk密钥"
    },
    {
        "Rule": r'["\']?open[_-]?whisk[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OpenWhisk密钥"
    },
    {
        "Rule": r'["\']?onesignal[_-]?user[_-]?auth[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OneSignal用户认证密钥"
    },
    {
        "Rule": r'["\']?onesignal[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OneSignal API密钥"
    },
    {
        "Rule": r'["\']?omise[_-]?skey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Omise密钥"
    },
    {
        "Rule": r'["\']?omise[_-]?pubkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Omise公钥"
    },
    {
        "Rule": r'["\']?omise[_-]?pkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Omise私钥"
    },
    {
        "Rule": r'["\']?omise[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Omise密钥"
    },
    {
        "Rule": r'["\']?okta[_-]?oauth2[_-]?clientsecret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Okta OAuth2客户端密钥"
    },
    {
        "Rule": r'["\']?okta[_-]?oauth2[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Okta OAuth2客户端密钥"
    },
    {
        "Rule": r'["\']?okta[_-]?client[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Okta客户端令牌"
    },
    {
        "Rule": r'["\']?ofta[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OFTA密钥"
    },
    {
        "Rule": r'["\']?ofta[_-]?region["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OFTA区域"
    },
    {
        "Rule": r'["\']?ofta[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OFTA密钥"
    },
    {
        "Rule": r'["\']?octest[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OCTest密码"
    },
    {
        "Rule": r'["\']?octest[_-]?app[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OCTest应用用户名"
    },
    {
        "Rule": r'["\']?octest[_-]?app[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OCTest应用密码"
    },
    {
        "Rule": r'["\']?oc[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OC密码"
    },
    {
        "Rule": r'["\']?object[_-]?store[_-]?creds["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对象存储凭证"
    },
    {
        "Rule": r'["\']?object[_-]?store[_-]?bucket["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对象存储桶"
    },
    {
        "Rule": r'["\']?object[_-]?storage[_-]?region[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对象存储区域名称"
    },
    {
        "Rule": r'["\']?object[_-]?storage[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对象存储密码"
    },
    {
        "Rule": r'["\']?oauth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "OAuth认证令牌"
    },
    {
        "Rule": r'["\']?numbers[_-]?service[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数字服务密码"
    },
    {
        "Rule": r'["\']?nuget[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NuGet密钥"
    },
    {
        "Rule": r'["\']?nuget[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NuGet API密钥"
    },
    {
        "Rule": r'["\']?nuget[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NuGet API密钥"
    },
    {
        "Rule": r'["\']?npm[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM令牌"
    },
    {
        "Rule": r'["\']?npm[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM密钥"
    },
    {
        "Rule": r'["\']?npm[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM密码"
    },
    {
        "Rule": r'["\']?npm[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM邮箱"
    },
    {
        "Rule": r'["\']?npm[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM认证令牌"
    },
    {
        "Rule": r'["\']?npm[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM API令牌"
    },
    {
        "Rule": r'["\']?npm[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "NPM API密钥"
    },
    {
        "Rule": r'["\']?now[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Now令牌"
    },
    {
        "Rule": r'["\']?non[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "非令牌"
    },
    {
        "Rule": r'["\']?node[_-]?pre[_-]?gyp[_-]?secretaccesskey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Node-pre-gyp密钥"
    },
    {
        "Rule": r'["\']?node[_-]?pre[_-]?gyp[_-]?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Node-pre-gyp GitHub令牌"
    },
    {
        "Rule": r'["\']?node[_-]?pre[_-]?gyp[_-]?accesskeyid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Node-pre-gyp访问密钥ID"
    },
    {
        "Rule": r'["\']?node[_-]?env["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Node环境变量"
    },
    {
        "Rule": r'["\']?ngrok[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Ngrok令牌"
    },
    {
        "Rule": r'["\']?ngrok[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Ngrok认证令牌"
    },
    {
        "Rule": r'["\']?nexuspassword["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Nexus密码"
    },
    {
        "Rule": r'["\']?nexus[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Nexus密码"
    },
    {
        "Rule": r'["\']?new[_-]?relic[_-]?beta[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "New Relic测试令牌"
    },
    {
        "Rule": r'["\']?netlify[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Netlify API密钥"
    },
    {
        "Rule": r'["\']?nativeevents["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "原生事件"
    },
    {
        "Rule": r'["\']?mysqlsecret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL密钥"
    },
    {
        "Rule": r'["\']?mysqlmasteruser["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL主用户"
    },
    {
        "Rule": r'["\']?mysql[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL用户名"
    },
    {
        "Rule": r'["\']?mysql[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL用户"
    },
    {
        "Rule": r'["\']?mysql[_-]?root[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL根用户密码"
    },
    {
        "Rule": r'["\']?mysql[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL密码"
    },
    {
        "Rule": r'["\']?mysql[_-]?hostname["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL主机名"
    },
    {
        "Rule": r'["\']?mysql[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MySQL数据库"
    },
    {
        "Rule": r'["\']?my[_-]?secret[_-]?env["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "我的密钥环境变量"
    },
    {
        "Rule": r'["\']?multi[_-]?workspace[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "多工作区SID"
    },
    {
        "Rule": r'["\']?multi[_-]?workflow[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "多工作流SID"
    },
    {
        "Rule": r'["\']?multi[_-]?disconnect[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "多断开连接SID"
    },
    {
        "Rule": r'["\']?multi[_-]?connect[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "多连接SID"
    },
    {
        "Rule": r'["\']?multi[_-]?bob[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "多Bob SID"
    },
    {
        "Rule": r'["\']?minio[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MinIO密钥"
    },
    {
        "Rule": r'["\']?minio[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MinIO访问密钥"
    },
    {
        "Rule": r'["\']?mile[_-]?zero[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mile Zero密钥"
    },
    {
        "Rule": r'["\']?mh[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MH密码"
    },
    {
        "Rule": r'["\']?mh[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MH API密钥"
    },
    {
        "Rule": r'["\']?mg[_-]?public[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MG公共API密钥"
    },
    {
        "Rule": r'["\']?mg[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MG API密钥"
    },
    {
        "Rule": r'["\']?mapboxaccesstoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mapbox访问令牌"
    },
    {
        "Rule": r'["\']?mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mapbox AWS密钥"
    },
    {
        "Rule": r'["\']?mapbox[_-]?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mapbox AWS访问密钥ID"
    },
    {
        "Rule": r'["\']?mapbox[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mapbox API令牌"
    },
    {
        "Rule": r'["\']?mapbox[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mapbox访问令牌"
    },
    {
        "Rule": r'["\']?manifest[_-]?app[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "清单应用URL"
    },
    {
        "Rule": r'["\']?manifest[_-]?app[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "清单应用令牌"
    },
    {
        "Rule": r'["\']?mandrill[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mandrill API密钥"
    },
    {
        "Rule": r'["\']?managementapiaccesstoken["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "管理API访问令牌"
    },
    {
        "Rule": r'["\']?management[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "管理令牌"
    },
    {
        "Rule": r'["\']?manage[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "管理密钥"
    },
    {
        "Rule": r'["\']?manage[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "管理密钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?secret[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun密钥API密钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?pub[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun公钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?pub[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun公共API密钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?priv[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun私钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun密码"
    },
    {
        "Rule": r'["\']?mailgun[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun API密钥"
    },
    {
        "Rule": r'["\']?mailgun[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Mailgun API密钥"
    },
    {
        "Rule": r'["\']?mailer[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "邮件程序密码"
    },
    {
        "Rule": r'["\']?mailchimp[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MailChimp密钥"
    },
    {
        "Rule": r'["\']?mailchimp[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "MailChimp API密钥"
    },
    {
        "Rule": r'["\']?mail[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "邮件密码"
    },
    {
        "Rule": r'["\']?magento[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Magento密码"
    },
    {
        "Rule": r'["\']?magento[_-]?auth[_-]?username ["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Magento认证用户名"
    },
    {
        "Rule": r'["\']?magento[_-]?auth[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Magento认证密码"
    },
    {
        "Rule": r'["\']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lottie上传证书密钥存储密码"
    },
    {
        "Rule": r'["\']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lottie上传证书密钥密码"
    },
    # {
    #     "Rule": r'["\']?lottie[_-]?s3[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Lottie S3密钥"
    # },
    {
        "Rule": r'["\']?lottie[_-]?happo[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lottie Happo密钥"
    },
    {
        "Rule": r'["\']?lottie[_-]?happo[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lottie Happo API密钥"
    },
    {
        "Rule": r'["\']?looker[_-]?test[_-]?runner[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Looker测试运行客户端密钥"
    },
    {
        "Rule": r'["\']?ll[_-]?shared[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "LL共享密钥"
    },
    {
        "Rule": r'["\']?ll[_-]?publish[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "LL发布URL"
    },
    # {
    #     "Rule": r'["\']?linux[_-]?signing[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Linux签名密钥"
    # },
    {
        "Rule": r'["\']?linkedin[_-]?client[_-]?secretor lottie[_-]?s3[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "LinkedIn客户端密钥或Lottie S3 API密钥"
    },
    {
        "Rule": r'["\']?lighthouse[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lighthouse API密钥"
    },
    {
        "Rule": r'["\']?lektor[_-]?deploy[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lektor部署用户名"
    },
    {
        "Rule": r'["\']?lektor[_-]?deploy[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Lektor部署密码"
    },
    {
        "Rule": r'["\']?leanplum[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Leanplum密钥"
    },
    {
        "Rule": r'["\']?kxoltsn3vogdop92m["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "特殊密钥标识符"
    },
    {
        "Rule": r'["\']?kubeconfig["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kubernetes配置"
    },
    {
        "Rule": r'["\']?kubecfg[_-]?s3[_-]?path["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kubernetes配置S3路径"
    },
    {
        "Rule": r'["\']?kovan[_-]?private[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kovan以太坊私钥"
    },
    {
        "Rule": r'["\']?keystore[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "密钥库密码"
    },
    {
        "Rule": r'["\']?kafka[_-]?rest[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kafka REST URL"
    },
    {
        "Rule": r'["\']?kafka[_-]?instance[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kafka实例名称"
    },
    {
        "Rule": r'["\']?kafka[_-]?admin[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Kafka管理URL"
    },
    {
        "Rule": r'["\']?jwt[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "JWT密钥"
    },
    {
        "Rule": r'["\']?jdbc:mysql["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "JDBC MySQL连接字符串"
    },
    {
        "Rule": r'["\']?jdbc[_-]?host["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "JDBC主机"
    },
    {
        "Rule": r'["\']?jdbc[_-]?databaseurl["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "JDBC数据库URL"
    },
    {
        "Rule": r'["\']?itest[_-]?gh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "集成测试GitHub令牌"
    },
    {
        "Rule": r'["\']?ios[_-]?docs[_-]?deploy[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "iOS文档部署令牌"
    },
    {
        "Rule": r'["\']?internal[_-]?secrets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "内部密钥"
    },
    {
        "Rule": r'["\']?integration[_-]?test[_-]?appid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "集成测试应用ID"
    },
    {
        "Rule": r'["\']?integration[_-]?test[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "集成测试API密钥"
    },
    {
        "Rule": r'["\']?index[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "索引名称"
    },
    {
        "Rule": r'["\']?ij[_-]?repo[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "IJ仓库用户名"
    },
    {
        "Rule": r'["\']?ij[_-]?repo[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "IJ仓库密码"
    },
    {
        "Rule": r'["\']?hub[_-]?dxia2[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Hub DXIA2密码"
    },
    {
        "Rule": r'["\']?homebrew[_-]?github[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Homebrew GitHub API令牌"
    },
    {
        "Rule": r'["\']?hockeyapp[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "HockeyApp令牌"
    },
    {
        "Rule": r'["\']?heroku[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Heroku令牌"
    },
    {
        "Rule": r'["\']?heroku[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Heroku邮箱"
    },
    {
        "Rule": r'["\']?heroku[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Heroku API密钥"
    },
    # {
    #     "Rule": r'["\']?hb[_-]?codesign[_-]?key[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "HB代码签名密钥密码"
    # },
    {
        "Rule": r'["\']?hb[_-]?codesign[_-]?gpg[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "HB代码签名GPG密码"
    },
    {
        "Rule": r'["\']?hab[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Habitat密钥"
    },
    {
        "Rule": r'["\']?hab[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Habitat认证令牌"
    },
    {
        "Rule": r'["\']?grgit[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Grgit用户"
    },
    {
        "Rule": r'["\']?gren[_-]?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Gren GitHub令牌"
    },
    {
        "Rule": r'["\']?gradle[_-]?signing[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Gradle签名密码"
    },
    # {
    #     "Rule": r'["\']?gradle[_-]?signing[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Gradle签名密钥ID"
    # },
    {
        "Rule": r'["\']?gradle[_-]?publish[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Gradle发布密钥"
    },
    {
        "Rule": r'["\']?gradle[_-]?publish[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Gradle发布密钥"
    },
    {
        "Rule": r'["\']?gpg[_-]?secret[_-]?keys["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG密钥"
    },
    {
        "Rule": r'["\']?gpg[_-]?private[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG私钥"
    },
    {
        "Rule": r'["\']?gpg[_-]?passphrase["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG密码短语"
    },
    {
        "Rule": r'["\']?gpg[_-]?ownertrust["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG所有者信任"
    },
    {
        "Rule": r'["\']?gpg[_-]?keyname["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG密钥名称"
    },
    {
        "Rule": r'["\']?gpg[_-]?key[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG密钥名称"
    },
    {
        "Rule": r'["\']?google[_-]?private[_-]?key[_-]?(id)?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google私钥ID"
    },
    {
        "Rule": r'["\']?google[_-]?maps[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google地图API密钥"
    },
    {
        "Rule": r'["\']?google[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google客户端密钥"
    },
    {
        "Rule": r'["\']?google[_-]?client[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google客户端ID"
    },
    {
        "Rule": r'["\']?google[_-]?client[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google客户端邮箱"
    },
    {
        "Rule": r'["\']?google[_-]?account[_-]?type["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Google账户类型"
    },
    {
        "Rule": r'["\']?gogs[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Gogs密码"
    },
    {
        "Rule": r'["\']?gitlab[_-]?user[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitLab用户邮箱"
    },
    {
        "Rule": r'["\']?github[_-]?tokens["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub令牌集合"
    },
    {
        "Rule": r'["\']?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub令牌"
    },
    {
        "Rule": r'["\']?github[_-]?repo["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub仓库"
    },
    {
        "Rule": r'["\']?github[_-]?release[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub发布令牌"
    },
    {
        "Rule": r'["\']?github[_-]?pwd["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub密码"
    },
    {
        "Rule": r'["\']?github[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub密码"
    },
    {
        "Rule": r'["\']?github[_-]?oauth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub OAuth令牌"
    },
    {
        "Rule": r'["\']?github[_-]?oauth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub OAuth"
    },
    {
        "Rule": r'["\']?github[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub密钥"
    },
    {
        "Rule": r'["\']?github[_-]?hunter[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub Hunter用户名"
    },
    {
        "Rule": r'["\']?github[_-]?hunter[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub Hunter令牌"
    },
    {
        "Rule": r'["\']?github[_-]?deployment[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub部署令牌"
    },
    {
        "Rule": r'["\']?github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub部署HB文档密码"
    },
    {
        "Rule": r'["\']?github[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub客户端密钥"
    },
    {
        "Rule": r'["\']?github[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub认证令牌"
    },
    {
        "Rule": r'["\']?github[_-]?auth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub认证"
    },
    {
        "Rule": r'["\']?github[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub API令牌"
    },
    {
        "Rule": r'["\']?github[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub API密钥"
    },
    {
        "Rule": r'["\']?github[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GitHub访问令牌"
    },
    {
        "Rule": r'["\']?env[_-]?github[_-]?oauth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "环境GitHub OAuth令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?end[_-]?user[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "终端用户密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?encryption[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "加密密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?elasticsearch[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Elasticsearch密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?elastic[_-]?cloud[_-]?auth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Elastic Cloud认证",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'["\']?dsonar[_-]?projectkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "Sonar项目密钥",
    #     "Level": "orange_tag"
    # },
    {
        "Rule": r'["\']?dsonar[_-]?login["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Sonar登录信息",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?droplet[_-]?travis[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Droplet Travis密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?dropbox[_-]?oauth[_-]?bearer["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Dropbox OAuth令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?doordash[_-]?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DoorDash认证令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?dockerhubpassword["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker Hub密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?dockerhub[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker Hub密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?postgres[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker Postgres URL",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?passwd["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?docker[_-]?hub[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Docker Hub密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?digitalocean[_-]?ssh[_-]?key[_-]?ids["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DigitalOcean SSH密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?digitalocean[_-]?ssh[_-]?key[_-]?body["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DigitalOcean SSH密钥内容",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?digitalocean[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DigitalOcean访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?dgpg[_-]?passphrase["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "GPG密码短语",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?deploy[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "部署用户",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?deploy[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "部署令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?deploy[_-]?secure["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "部署安全密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?deploy[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "部署密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?ddgc[_-]?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DDGC GitHub令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?ddg[_-]?test[_-]?email[_-]?pw["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DDG测试邮箱密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?ddg[_-]?test[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "DDG测试邮箱",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?db[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库用户名",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?db[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库用户",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?db[_-]?pw["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?db[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?db[_-]?host["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库主机",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?db[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库名称",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?db[_-]?connection["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库连接",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?datadog[_-]?app[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Datadog应用密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?datadog[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Datadog API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?database[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库用户名",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?database[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库用户",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?database[_-]?port["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库端口",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?database[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?database[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库名称",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?database[_-]?host["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "数据库主机",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?danger[_-]?github[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Danger GitHub API令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cypress[_-]?record[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cypress记录密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?coverity[_-]?scan[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Coverity扫描令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?coveralls[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Coveralls令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?coveralls[_-]?repo[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Coveralls仓库令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?coveralls[_-]?api[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Coveralls API令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cos[_-]?secrets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "COS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?conversation[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对话用户名",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?conversation[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "对话密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?v2[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful V2访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?test[_-]?org[_-]?cma[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful测试组织CMA令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?php[_-]?management[_-]?test[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful PHP管理测试令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful管理API新访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?management[_-]?api[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful管理API访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?integration[_-]?management[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful集成管理令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?cma[_-]?test[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful CMA测试令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?contentful[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Contentful访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?consumerkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "消费者密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?consumer[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "消费者密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?conekta[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Conekta API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?coding[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Coding令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?codecov[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Codecov令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?codeclimate[_-]?repo[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CodeClimate仓库令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?codacy[_-]?project[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Codacy项目令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cocoapods[_-]?trunk[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CocoaPods Trunk令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cocoapods[_-]?trunk[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CocoaPods Trunk邮箱",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cn[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CN密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cn[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CN访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?clu[_-]?ssh[_-]?private[_-]?key[_-]?base64["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CLU SSH私钥Base64",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?clu[_-]?repo[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CLU仓库URL",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudinary[_-]?url[_-]?staging["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudinary暂存URL",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudinary[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudinary URL",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudflare[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudflare邮箱",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudflare[_-]?auth[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudflare认证密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cloudflare[_-]?auth[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudflare认证邮箱",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudflare[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudflare API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?service[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant服务数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?processed[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant处理数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?parsed[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant解析数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?order[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant订单数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?instance["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant实例",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?audited[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant审计数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloudant[_-]?archived[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cloudant归档数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?cloud[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "云API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?clojars[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Clojars密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "客户端密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cli[_-]?e2e[_-]?cma[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CLI E2E CMA令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?claimr[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Claimr令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?claimr[_-]?superuser["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Claimr超级用户",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?claimr[_-]?db["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Claimr数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?claimr[_-]?database["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Claimr数据库",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?ci[_-]?user[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CI用户令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?ci[_-]?server[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CI服务器名称",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?ci[_-]?registry[_-]?user["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CI注册表用户",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?ci[_-]?project[_-]?url["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CI项目URL",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?ci[_-]?deploy[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CI部署密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?chrome[_-]?refresh[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Chrome刷新令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?chrome[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Chrome客户端密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cheverny[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cheverny令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cf[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "CF密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?certificate[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "证书密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?censys[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Censys密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cattle[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cattle密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cattle[_-]?agent[_-]?instance[_-]?auth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cattle代理实例认证",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cattle[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cattle访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?cargo[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Cargo令牌",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'["\']?cache[_-]?s3[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "缓存S3密钥",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'["\']?bx[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "BX用户名",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?bx[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "BX密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bundlesize[_-]?github[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bundlesize GitHub令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?built[_-]?branch[_-]?deploy[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构建分支部署密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bucketeer AWS密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bucketeer AWS访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?browserstack[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "BrowserStack访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?browser[_-]?stack[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Browser Stack访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?brackets[_-]?repo[_-]?oauth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Brackets仓库OAuth令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix用户名",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?pwd["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?pass[_-]?prod["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix生产密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?auth["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix认证",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bluemix[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bluemix API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintraykey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintray[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintray[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintray[_-]?gpg[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray GPG密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintray[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?bintray[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Bintray API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?b2[_-]?bucket["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "B2存储桶",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?b2[_-]?app[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "B2应用密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?awssecretkey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?awscn[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS中国区密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?awscn[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS中国区访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?awsaccesskeyid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?ses[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS SES密钥访问密钥",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'["\']?aws[_-]?ses[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "AWS SES访问密钥ID",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'["\']?aws[_-]?secrets["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?config[_-]?secretaccesskey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS配置密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?config[_-]?accesskeyid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS配置访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aws[_-]?access["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AWS访问",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?author[_-]?npm[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "作者NPM API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?author[_-]?email[_-]?addr["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "作者邮箱地址",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?auth0[_-]?client[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Auth0客户端密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?auth0[_-]?api[_-]?clientsecret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Auth0 API客户端密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?auth[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "认证令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?assistant[_-]?iam[_-]?apikey["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Assistant IAM API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?artifacts[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构件密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?artifacts[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构件密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?artifacts[_-]?bucket["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构件存储桶",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构件AWS密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?artifacts[_-]?aws[_-]?access[_-]?key[_-]?id["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "构件AWS访问密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?artifactory[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Artifactory密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?argos[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Argos令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?apple[_-]?id[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Apple ID密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?appclientsecret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "应用客户端密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?app[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "应用令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?app[_-]?secrete["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "应用密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?app[_-]?report[_-]?token[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "应用报告令牌密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?app[_-]?bucket[_-]?perm["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "应用存储桶权限",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?apigw[_-]?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "API网关访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?apiary[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Apiary API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?api[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?api[_-]?key[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "API密钥SID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?api[_-]?key[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "API密钥Secret",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aos[_-]?sec["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AOS安全密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?aos[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "AOS密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?ansible[_-]?vault[_-]?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Ansible保险库密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?android[_-]?docs[_-]?deploy[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Android文档部署令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?anaconda[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Anaconda令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?amazon[_-]?secret[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Amazon密钥访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?amazon[_-]?bucket[_-]?name["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Amazon存储桶名称",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?alicloud[_-]?secret[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "阿里云密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?alicloud[_-]?access[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "阿里云访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?alias[_-]?pass["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "别名密码",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?search[_-]?key[_-]?1["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia搜索密钥1",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?search[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia搜索密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?search[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia搜索API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?api[_-]?key[_-]?search["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia搜索API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?api[_-]?key[_-]?mcm["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia MCM API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?admin[_-]?key[_-]?mcm["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia MCM管理密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?admin[_-]?key[_-]?2["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia管理密钥2",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?algolia[_-]?admin[_-]?key[_-]?1["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Algolia管理密钥1",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?air[-_]?table[-_]?api[-_]?key["\']?[=:]["\'"].+["\']',
        "VerboseName": "Airtable API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?adzerk[_-]?api[_-]?key["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "Adzerk API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?admin[_-]?email["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "管理员邮箱",
        "Level": "orange_tag"
    },
    {
        "Rule": r'["\']?account[_-]?sid["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "账户SID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?access[_-]?token["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?access[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "访问密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?access[_-]?key[_-]?secret["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "访问密钥Secret",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'["\']?account["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "账户",
    #     "Level": "orange_tag"
    # },
    # {
    #     "Rule": r'["\']?password["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "密码",
    #     "Level": "red_tag"
    # },
    # {
    #     "Rule": r'["\']?username["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "用户名",
    #     "Level": "orange_tag"
    # },
    # {
    #     "Rule": r'["\']?[\w_-]*?password[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "通用密码",
    #     "Level": "red_tag"
    # },
    # {
    #     "Rule": r'["\']?[\w_-]*?name[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "通用用户名",
    #     "Level": "orange_tag"
    # },
    # {
    #     "Rule": r'["\']?[\w_-]*?accesskey[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "通用访问密钥",
    #     "Level": "red_tag"
    # },
    # {
    #     "Rule": r'["\']?[\w_-]*?secret[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "通用密钥",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'["\']?[\w_-]*?bucket[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "通用存储桶",
        "Level": "orange_tag"
    },
    # {
    #     "Rule": r'["\']?[\w_-]*?token[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
    #     "VerboseName": "通用令牌",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'["\']?[-]+BEGIN \w+ PRIVATE KEY[-]+',
        "VerboseName": "私钥开始行",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?huawei\.oss\.(ak|sk|bucket\.name|endpoint|local\.path)["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "华为云OSS配置",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?private[_-]?key[_-]?(id)?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "私钥标识",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?account[_-]?(name|key)?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?',
        "VerboseName": "账户信息",
        "Level": "orange_tag"
    },
    {
        "Rule": r'LTAI[A-Za-z\d]{12,30}',
        "VerboseName": "阿里云AccessKey ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'AKID[A-Za-z\d]{13,40}',
        "VerboseName": "腾讯云AccessKey ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'JDC_[0-9A-Z]{25,40}',
        "VerboseName": "京东云AccessKey",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\']?(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']?',
        "VerboseName": "AWS密钥ID",
        "Level": "red_tag"
    },
    {
        "Rule": r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}',
        "VerboseName": "阿里云密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'AKLT[a-zA-Z0-9-_]{16,28}',
        "VerboseName": "阿里云密钥简短格式",
        "Level": "red_tag"
    },
    {
        "Rule": r'AIza[0-9A-Za-z_\-]{35}',
        "VerboseName": "Google API密钥",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}',
    #     "VerboseName": "Bearer认证令牌",
    #     "Level": "red_tag"
    # },
    # {
    #     "Rule": r'[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}',
    #     "VerboseName": "Basic认证",
    #     "Level": "red_tag"
    # },
    # {
    #     "Rule": r'["\'\[\]]*[Aa]uthorization["\'\]\[]*\s*[:=]\s*["\'](?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}["\'"]?',
    #     "VerboseName": "认证头信息",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'(glpat-[a-zA-Z0-9\-=_]{20,22})',
        "VerboseName": "GitLab个人访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})',
        "VerboseName": "GitHub个人访问令牌",
        "Level": "red_tag"
    },
    {
        "Rule": r'APID[a-zA-Z0-9]{32,42}',
        "VerboseName": "API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\'](wx[a-z0-9]{15,18})["\']',
        "VerboseName": "微信公众号AppID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\'](ww[a-z0-9]{15,18})["\']',
        "VerboseName": "企业微信CorpID",
        "Level": "red_tag"
    },
    {
        "Rule": r'["\'](gh_[a-z0-9]{11,13})["\']',
        "VerboseName": "微信公众号原始ID",
        "Level": "red_tag"
    },
    # {
    #     "Rule": r'(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)\\?[\'"]?*\s*[:=]\s*\\?[\'"][a-z0-9!@#$%&*]{5,20}\\?[\'"]',
    #     "VerboseName": "通用密码配置",
    #     "Level": "red_tag"
    # },
    {
        "Rule": r'https:\/\/qyapi\.weixin\.qq\.com\/cgi\-bin\/webhook\/send\?key=[a-zA-Z0-9\-]{25,50}',
        "VerboseName": "企业微信群机器人Webhook",
        "Level": "red_tag"
    },
    {
        "Rule": r'https:\/\/oapi\.dingtalk\.com\/robot\/send\?access_token=[a-z0-9]{50,80}',
        "VerboseName": "钉钉群机器人Webhook",
        "Level": "red_tag"
    },
    {
        "Rule": r'https:\/\/open\.feishu\.cn\/open\-apis\/bot\/v2\/hook\/[a-z0-9\-]{25,50}',
        "VerboseName": "飞书群机器人Webhook",
        "Level": "red_tag"
    },
    {
        "Rule": r'https:\/\/hooks\.slack\.com\/services\/[a-zA-Z0-9\-_]{6,12}\/[a-zA-Z0-9\-_]{6,12}\/[a-zA-Z0-9\-_]{15,24}',
        "VerboseName": "Slack Webhook",
        "Level": "red_tag"
    },
    {
        "Rule": r'eyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}',
        "VerboseName": "Grafana API密钥",
        "Level": "red_tag"
    },
    {
        "Rule": r'glc_[A-Za-z0-9\-_+/]{32,200}={0,2}',
        "VerboseName": "GitLab CI变量",
        "Level": "red_tag"
    },
    {
        "Rule": r'glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}',
        "VerboseName": "GitLab共享访问令牌",
        "Level": "red_tag"
    }
]

# HaE 正则表达式
HaE_rules = [
    {
        "Rule": "(=deleteMe|rememberMe=)",
        "VerboseName": "Shiro Cookie"
    },
    {
        "Rule": "(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,})",
        "VerboseName": "JSON Web Token (JWT)"
    },
    {
        "Rule": "((swagger-ui.html)|(\\\"swagger\\\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))",
        "VerboseName": "Swagger UI"
    },
    {
        "Rule": "(ueditor\\.(config|all)\\.js)",
        "VerboseName": "Ueditor"
    },
    {
        "Rule": "(Druid Stat Index)",
        "VerboseName": "Druid"
    },
    # {
    #     "Rule": "(pdf.worker)",
    #     "VerboseName": "PDF.js 查看器"
    # },
    {
        "Rule": "(javax\\.faces\\.ViewState)",
        "VerboseName": "Java 反序列化"
    },
    # {
    #     "Rule": r"((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))",
    #     "VerboseName": "调试逻辑参数"
    # },
    # {
    #     "Rule": r"(=(https?)(://|%3a%2f%2f))",
    #     "VerboseName": "URL 作为值"
    # },
    # {
    #     "Rule": r"(type\\=\\\"file\\\")",
    #     "VerboseName": "上传表单"
    # },
    # {
    #     "Rule": r"((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))",
    #     "VerboseName": "DoS 参数"
    # },
    # {
    #     "Rule": r"(([a-z0-9]+[_|\\.])*[a-z0-9]+@([a-z0-9]+[-|_|\\.])*[a-z0-9]+\\.((?!js|css|jpg|jpeg|png|ico)[a-z]{2,5}))",
    #     "VerboseName": "电子邮件"
    # },
    {
        "Rule": "[^0-9]((\\d{8}(0\\d|10|11|12)([0-2]\\d|30|31)\\d{3}$)|(\\d{6}(18|19|20)\\d{2}(0[1-9]|10|11|12)([0-2]\\d|30|31)\\d{3}(\\d|X|x)))[^0-9]",
        "VerboseName": "中国身份证号"
    },
    {
        "Rule": "[^\\w]((?:(?:\\+|0{0,2})86)?1(?:(?:3[\\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\\d])|(?:9[189]))\\d{8})[^\\w]",
        "VerboseName": "中国手机号"
    },
    # {
    #     "Rule": r"[^0-9]((127\\.0\\.0\\.1)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3}))",
    #     "VerboseName": "内网IP地址"
    # },
    # {
    #     "Rule": r"(^([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})|[^a-zA-Z0-9]([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}))",
    #     "VerboseName": "MAC地址"
    # },
    {
        "Rule": r"\b(?:access[-_]?key[-_]?id|secret[-_]?access[-_]?key)\b[^\w]*([A-Z0-9]{20})(?:[^\w]*\b([A-Z0-9]{40})\b)?",
        "VerboseName": "云密钥"
    },
    # {
    #     "Rule": r"""(?:^|[^\w])(?:(?:[a-zA-Z]:|\\\\[^<>:/\\|?*"']+\\[^<>:/\\|?*"']+)\\(?:[^<>:/\\|?*"']+\\)*)([^<>:/\\|?*"']+(?:\.[^<>:/\\|?*"']{1,10})?)""",
    #     "VerboseName": "Windows 文件/目录路径"
    # },
    # {
    #     "Rule": r"(((|\\\\)(|'|\")(|[\\.\\w]{1,10})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
    #     "VerboseName": "密码字段"
    # },
    # {
    #     "Rule": r"(((|\\\\)(|'|\")(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
    #     "VerboseName": "用户名字段"
    # },
    {
        "Rule": "((corp)(id|secret))",
        "VerboseName": "企业微信密钥"
    },
    {
        "Rule": "(jdbc:[a-z:]+://[a-z0-9\\.\\-_:;=/@?,\u0026]+)",
        "VerboseName": "JDBC连接"
    },
    # {
    #     "Rule": "((basic [a-z0-9=:_\\+\\/-]{5,100})|(bearer [a-z0-9_.=:_\\+\\/-]{5,100}))",
    #     "VerboseName": "授权头"
    # },
    # {
    #     "Rule": "(((\\[)?('|\")?([\\.\\w]{0,10})(key|secret|token|config|auth|access|admin|ticket)([\\.\\w]{0,10})('|\")?(\\])?( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)('|\")([^'\"]+?)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(key|secret|token|config|auth|access|admin|ticket)(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
    #     "VerboseName": "敏感字段"
    # },
    # {
    #     "Rule": "(((\\[)?('|\")?([\\.\\w]{0,10})(key|secret|token|admin|ticket)([\\.\\w]{0,10})('|\")?(\\])?( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)('|\")([^'\"]+?)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(key|secret|token|config|auth|access|admin|ticket)(|[\\.\\w]{1,10})(|\\\\)(|'|\")))",
    #     "VerboseName": "敏感字段"
    # },
    {
        "Rule": "(((|\\\\)(|'|\")(|[\\w]{1,10})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,10})(|\\\\)(|'|\")( |)(:|=|!=|[\\)]{0,1}\\.val\\()( |)(|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|,|\\)))|((|\\\\)('|\")([^'\"]+?)(|\\\\)('|\")(|\\\\)(|'|\")( |)(:|[=]{1,3}|![=]{1,2})( |)(|[\\.\\w]{1,10})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,10})(|\\\\)(|'|\"))) ",
        "VerboseName": "手机号字段"
    },
    # ,
    # {
    #     "Rule": "(?:\"|')((?:(?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,}))(?:(?:\"|')|\\s|$)",
    #     "VerboseName": "URL 字段"
    # }
]

# 接口正则表达式
path_rules = [
    # {
    #     "Rule": r"['\"]((([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|tw|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\:\d{1,5})?(\/)?)['\"]",
    #     "VerboseName": "域名提取"
    # },
    {
        "Rule": r"['\"](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['\"]",
        "VerboseName": "绝对路径"
    }
    # {
    #     "Rule": r"['\"][^\/\>\< \)\(\{\}\,\'\"\\][\w\/]*?\/[\w\/]*?['\"]",
    #     "VerboseName": "相对路径"
    # }
]

# 静态文件后缀集合，排除匹配路径内容包含静态文件后缀的
static_extension = [
    # 前端/样式/模板/脚本
    '.js', '.mjs', '.vue', '.scss', '.less', '.css', '.wxml', '.wxss', 
    '.ah', '.wasm', '.swf', '.wxs', '.dtd', '.fdf', '.tnpmrc', '.tnpm', '.left',

    # 图片
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', 
    '.tiff', '.tif', '.apng', '.avif', '.jfif', '.pjpeg', '.pjp', 
    '.cur', '.ani', '.jng', '.jp2', '.j2k', '.jpf', '.jpx', '.jpm', 
    '.mj2', '.svgz', '.wdp', '.hdp', '.bpg', '.exr', '.hdr', '.pic', 
    '.raw', '.rgb', '.rgba', '.sgi', '.tga', '.yuv',

    # 字体
    '.ttf', '.otf', '.woff', '.woff2', '.eot', '.fon', '.fnt',

    # 音频
    '.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac', '.amr', 
    '.aiff', '.wma', '.mid', '.midi',

    # 视频
    '.mp4', '.m4v', '.mov', '.avi', '.wmv', '.flv', '.webm', 
    '.mkv', '.3gp', '.3g2', '.ts', '.ogv', '.vob', '.mpg', 
    '.mpeg', '.f4v', '.mpe', '.mpv', '.m2v', '.mts', '.m2ts', 
    '.divx', '.dv', '.rm', '.ram', '.qt',

    # 设计源文件
    '.psd', '.ai', '.sketch', '.xcf', '.icns', '.pat', '.abr', 
    '.ase', '.aseprite', '.gbr', '.gih',

    # 压缩包
    '.crx','.dig','ui','.info','.min','.util','.cookie'
]

# 排除不带接口信息的静态文件
static_file_extensions = [
    # 图片
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', 
    '.tiff', '.tif', '.apng', '.avif', '.jfif', '.pjpeg', '.pjp', 
    '.cur', '.ani', '.jng', '.jp2', '.j2k', '.jpf', '.jpx', '.jpm', 
    '.mj2', '.svgz', '.wdp', '.hdp', '.bpg', '.exr', '.hdr', '.pic', 
    '.raw', '.rgb', '.rgba', '.sgi', '.tga', '.yuv', '.css',

    # 字体
    '.ttf', '.otf', '.woff', '.woff2', '.eot', '.fon', '.fnt',

    # 音频
    '.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac', '.amr', 
    '.aiff', '.wma', '.mid', '.midi',

    # 视频
    '.mp4', '.m4v', '.mov', '.avi', '.wmv', '.flv', '.webm', 
    '.mkv', '.3gp', '.3g2', '.ts', '.ogv', '.vob', '.mpg', 
    '.mpeg', '.f4v', '.mpe', '.mpv', '.m2v', '.mts', '.m2ts', 
    '.divx', '.dv', '.rm', '.ram', '.qt',

    # 设计源文件
    '.psd', '.ai', '.sketch', '.xcf', '.icns', '.pat', '.abr', 
    '.ase', '.aseprite', '.gbr', '.gih',

    # 压缩包
    '.crx'
]

# 排除内容 相对路径
exclude_content = [
"text/css","text/html","text/javascript","../","./","application/json","text/plain","/#","*/","a/b","/a/b","/a/i","/","/./","&_","/a","/js/","/*$0*/"
]


# 排除请求包的类型
exclude_content = [
    "image/*", "audio/*", "video/*", "application/ogg","application/pdf","application/msword","application/x-ppt","video/avi","application/x-ico","*zip"
]