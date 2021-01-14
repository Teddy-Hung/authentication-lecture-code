insert into test_user (
    email,
    password
) values (
    ${email},
    ${hash}
)
returning user_id, email;