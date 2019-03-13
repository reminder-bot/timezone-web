CREATE TABLE timezone.user_guilds (
    cache_time INT UNSIGNED DEFAULT (UNIX_TIMESTAMP() + 7200) NOT NULL,
    user BIGINT NOT NULL,
    guild BIGINT NOT NULL
);