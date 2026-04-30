const AppState = {
    currentVaultPath: null,
    currentVaultMeta: null,

    setVault(path, meta = null) {
        this.currentVaultPath = path;
        this.currentVaultMeta = meta;
    },

    hasVault() {
        return Boolean(this.currentVaultPath);
    },
};