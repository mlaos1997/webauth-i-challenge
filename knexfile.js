// Update with your config settings.

module.exports = {

    development: {
        client: 'sqlite3',
        useNullAsDefault: true,
        connection: {
            filename: './data/authentication.db3'
        },
        migrations: {
          directory: './data/migrations'
        }
    }
};
