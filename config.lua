function permit_register_user(user)
    return true
end

function permit_set_password(user)
    return true
end

function permit_set_display_name(user)
    return true
end

function permit_get_display_name(user, target)
    return true
end

function permit_begin_session(user)
    return true
end

function permit_get_pubkey(user, target)
    return true
end

function permit_send_message(user, target)
    return true
end

function permit_check_online_status(user, target)
    return true
end

function permit_find_users_by_display_name(user, query)
    return true
end

function permit_find_users_by_login(user, query)
    return true
end

