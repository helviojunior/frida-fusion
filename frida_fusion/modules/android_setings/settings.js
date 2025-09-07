/*
Documentation
https://developer.android.com/reference/android/provider/Settings

*/

const SET_MODULES = {
    Global: true,
    Secure: true,
    System: true,
};

setTimeout(function() {
    Java.perform(function() {

        // Bypass Settings
        var androidSettings = [
            ['adb_enabled', 0],
            ['development_settings_enabled', 0],
            ['play_protect_enabled', 1],
            ['adb_enabled', 0]
        ];

        function settings_bypassValue(name, originalValue) {
            androidSettings.forEach(function(item) {
                let name = item[0];
                let value = item[1];

                if (name === name) {
                    fusion_sendMessage('D', `Bypassing ${name}`)
                    return value;
                }
            });
            return originalValue;
        }

        if (SET_MODULES.System) {

            fusion_sendMessage('D', "Module attached: android.provider.Settings.System");
            const settingsSystem = Java.use("android.provider.Settings$System");

            settingsSystem.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
                var data = this.getString.overload('android.content.ContentResolver', 'java.lang.String').call(this, cr, name);
                fusion_sendKeyValueData("Settings$System.getString", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return data
            };

            settingsSystem.putString.overload('android.content.ContentResolver', 'java.lang.String', 'java.lang.String').implementation = function (cr, name, value) {
                fusion_sendKeyValueData("Settings$System.putString", [
                    {key: "Name", value: name},
                    {key: "Value", value: value}
                ]);
                return this.putString.overload('android.content.ContentResolver', 'java.lang.String', 'java.lang.String').call(this, cr, name, value);
            };

            settingsSystem.getUriFor.overload('java.lang.String').implementation = function (name) {
                var data = this.getUriFor.overload('java.lang.String').call(this, name);
                fusion_sendKeyValueData("Settings$System.getUriFor", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return data
            };

            settingsSystem.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').call(this, cr, name, flag);
                fusion_sendKeyValueData("Settings$System.getInt", [
                    {key: "Name", value: name},
                    {key: "Flag", value: flag},
                    {key: "Result", value: data}
                ]);

                return settings_bypassValue(name, data);
            }

            settingsSystem.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String').call(this, cr, name);
                fusion_sendKeyValueData("Settings$System.getInt", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return settings_bypassValue(name, data);
            }

        }

        if (SET_MODULES.Secure) {

            fusion_sendMessage('D', "Module attached: android.provider.Settings.Secure");
            const settingsSecure = Java.use("android.provider.Settings$Secure");

            settingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
                var data = this.getString.overload('android.content.ContentResolver', 'java.lang.String').call(this, cr, name);
                fusion_sendKeyValueData("Settings$Secure.getString", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return data
            };

            settingsSecure.putString.overload('android.content.ContentResolver', 'java.lang.String', 'java.lang.String').implementation = function (cr, name, value) {
                fusion_sendKeyValueData("Settings$Secure.putString", [
                    {key: "Name", value: name},
                    {key: "Value", value: value}
                ]);
                return this.putString.overload('android.content.ContentResolver', 'java.lang.String', 'java.lang.String').call(this, cr, name, value);
            };

            settingsSecure.getUriFor.overload('java.lang.String').implementation = function (name) {
                var data = this.getUriFor.overload('java.lang.String').call(this, name);
                fusion_sendKeyValueData("Settings$Secure.getUriFor", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return data
            };

            settingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').call(this, cr, name, flag);
                fusion_sendKeyValueData("Settings$Secure.getInt", [
                    {key: "Name", value: name},
                    {key: "Flag", value: flag},
                    {key: "Result", value: data}
                ]);

                return settings_bypassValue(name, data);
            }

            settingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String').call(this, cr, name);
                fusion_sendKeyValueData("Settings$Secure.getInt", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return settings_bypassValue(name, data);
            }

        }

        if (SET_MODULES.Global) {

            fusion_sendMessage('D', "Module attached: android.provider.Settings.Global");
            const settingGlobal = Java.use('android.provider.Settings$Global');

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').call(this, cr, name, flag);
                fusion_sendKeyValueData("Settings$Global.getInt", [
                    {key: "Name", value: name},
                    {key: "Flag", value: flag},
                    {key: "Result", value: data}
                ]);
                return settings_bypassValue(name, data);
            }

            settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                var data = this.getInt.overload('android.content.ContentResolver', 'java.lang.String').call(this, cr, name);
                fusion_sendKeyValueData("Settings$Global.getInt", [
                    {key: "Name", value: name},
                    {key: "Result", value: data}
                ]);
                return settings_bypassValue(name, data);
            }

        }

        fusion_sendMessage("W", "Android Settings hook module have been successfully initialized.")
    });
    
}, 0);
