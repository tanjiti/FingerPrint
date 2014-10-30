FingerPrint
===========

web应用指纹识别

使用WWW::Wappalyzer进行的指纹识别
感谢https://github.com/ElbertF/Wappalyzer


运行说明
1. 安装WWW::Wappalyzer模块

cpan -i  WWW::Wappalyzer  



2. 运行

(1) 识别单个url指纹

perl FingerPrint.pl www.tanjiti.com<url>

输出结果为

{
        "www.tanjiti.com": {
                "web-servers": [
                        "Nginx"
                ],
                "cdn": [
                        "CloudFlare"
                ]
        }
}



(2) 使用自定义指纹文件进行识别

perl FingerPrint.pl http://www.xxx.com<url> tanjiti.json[rule_jsonfile] 

{
        "http://www.xxx.com": {
                "web-servers": [
                        "Nginx"
                ],
                "cms": [
                        "Discuz!"
                ]
        }
}

(3) 从文件读取url列表进行批量指纹识别，并将结果输出到文件中

perl FingerPrint.pl url.txt<url file> tanjiti.json[rule_jsonfile] 

结果输出到 url.txt__fingerprint 文件里

cat url.txt__fingerprint

{
        "http://www.xxxx.com": {
                "web-servers": [
                        "Nginx"
                ],
                "cms": [
                        "Discuz!"
                ]
        },
        "http://www.yyyyy.net": {
                "cms": [
                        "Discuz!"
                ]
        },
        "http://www.zzzz.cn": {
                "blogs": [
                        "WordPress"
                ],
                "web-servers": [
                        "Nginx"
                ],
                "cdn": [
                        "CloudFlare"
                ],
                "cms": [
                        "WordPress"
                ],
                "font-scripts": [
                        "Google Font API"
                ],
                "javascript-frameworks": [
                        "jQuery"
                ],
                "javascript-graphics": [
                        "Javascript Infovis Toolkit"
                ]
        }
}
