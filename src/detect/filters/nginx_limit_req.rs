use super::FilterTemplate;

pub const FILTER: FilterTemplate = FilterTemplate {
    name: "nginx-limit-req",
    description: "Nginx rate limit and connection limit violations",
    log_path: "/var/log/nginx/error.log",
    date_format: "common",
    patterns: &[
        r"limiting requests, excess: .* by zone .*, client: <HOST>,",
        r"limiting connections by zone .*, client: <HOST>,",
        r"delaying request.* by zone .*, client: <HOST>,",
    ],
};

#[cfg(test)]
mod tests {
    use crate::detect::filters::test_util::assert_filter_matches;

    #[test]
    fn nginx_limit_req_limiting_requests() {
        assert_filter_matches(
            "nginx-limit-req",
            r#"2015/10/29 20:01:02 [error] 256554#0: *99927 limiting requests, excess: 1.852 by zone "one", client: 1.2.3.4, server: example.com, request: "POST /index.htm HTTP/1.0", host: "example.com""#,
            "1.2.3.4",
        );
    }

    #[test]
    fn nginx_limit_req_ipv6() {
        assert_filter_matches(
            "nginx-limit-req",
            r#"2016/09/30 08:36:06 [error] 22923#0: *4758725916 limiting requests, excess: 15.243 by zone "one", client: 2001:db8::80da:af6b:8b2c, server: example.com, request: "GET / HTTP/1.1", host: "example.com""#,
            "2001:db8::80da:af6b:8b2c",
        );
    }

    #[test]
    fn nginx_limit_req_delaying() {
        assert_filter_matches(
            "nginx-limit-req",
            r#"2025/08/01 04:24:17 [warn] 4772#4772: *68 delaying request, excess: 0.841, by zone "req_limit", client: 206.189.215.97, server: myserver.net, request: "GET /ab2h HTTP/1.1", host: "22.18.134.49""#,
            "206.189.215.97",
        );
    }

    #[test]
    fn nginx_limit_req_connections() {
        assert_filter_matches(
            "nginx-limit-req",
            r#"2025/08/03 03:17:28 [error] 25808#25808: *598 limiting connections by zone "conn_limit", client: 128.199.22.141, server: myserver.net, request: "GET /favicon.ico HTTP/1.1", host: "84.108.142.49", referrer: "https://xxx.com/""#,
            "128.199.22.141",
        );
    }
}
