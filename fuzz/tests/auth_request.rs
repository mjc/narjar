#[test]
fn authorization_fuzzing_reaches_both_permission_checks() {
    let requests: &[(&[u8], bool)] = &[
        (b"GET / HTTP/1.1\r\n\r\n", false),
        (
            b"GET / HTTP/1.1\r\nAuthorization: Basic OmZ1enotdG9rZW4=\r\n\r\n",
            true,
        ),
        (
            b"GET / HTTP/1.1\r\nAuthorization: Basic Ondyb25n\r\n\r\n",
            false,
        ),
    ];
    for &(request, accepted) in requests {
        assert_eq!(
            narjar_fuzz::auth_request(request),
            Some((accepted, accepted))
        );
    }
}
