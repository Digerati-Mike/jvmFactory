/**
* @author       Media3 Development Team
* @version      2.0.0
* @since        2026-07-01
* @description  Tracks and modifies ColdFusion JVM arguments introduced by security/breaking-change
*               updates, flags insecure values, and produces a weighted secure score. Every public
*               method authenticates against the ColdFusion Administrator before touching the runtime.
*               Argument metadata is sourced from the per-version catalog files (catalog.2025.json,
*               catalog.2023.json, catalog.2021.json) built from the two Adobe JVM argument guides.
*               Self-contained: does not extend or depend on any sibling component. The only external
*               references are ColdFusion's built-in cfide.adminapi.* server API (required to validate
*               the administrator and to read/write JVM arguments).
*/
component accessors="true" {

    property name="userName"     type="string" default="" hint="Administrator user id used for authentication.";
    property name="password"     type="string" default="" hint="Administrator password used for authentication.";
    property name="cf_version"   type="string" default="2025" hint="Major ColdFusion version (2025 / 2023 / 2021).";
    property name="catalog_file" type="string" default="catalog.2025.json" hint="File name of the version-specific JVM argument catalog.";
    property name="catalog_path" type="string" hint="Resolved absolute path to the catalog file.";
    property name="backup_dir"     type="string" hint="Resolved absolute path to the ./_backups/ directory (relative to this component).";
    property name="jvmConfig_path" type="string" hint="Resolved absolute path to the server jvm.config file.";

    /**
     * @hint Initialise the client and resolve the catalog path. Credentials are supplied here
     *       (userName/password) via dynamicProperties.
    */
    public jvmFactory function init( required struct dynamicProperties = {} ) {

        structAppend( variables, arguments.dynamicProperties, true );

        variables.cf_version = listFirst( server.coldfusion.productversion );

        if ( !structKeyExists( variables, "catalog_file" ) || !len( trim( variables.catalog_file ) ) ) {
            variables.catalog_file = "catalog." & variables.cf_version & ".json";
        }

        if ( !structKeyExists( variables, "catalog_path" ) || !len( trim( variables.catalog_path ) ) ) {
            variables.catalog_path = getDirectoryFromPath( getCurrentTemplatePath() ) & variables.catalog_file;
        }

        if ( !structKeyExists( variables, "backup_dir" ) || !len( trim( variables.backup_dir ) ) ) {
            variables.backup_dir = getDirectoryFromPath( getCurrentTemplatePath() ) & "_backups" & server.system.properties['file.separator'];
        }

        if ( !structKeyExists( variables, "jvmConfig_path" ) || !len( trim( variables.jvmConfig_path ) ) ) {
            variables.jvmConfig_path = server.coldfusion.rootDir & server.system.properties['file.separator'] & "bin" & server.system.properties['file.separator'] & "jvm.config";
        }

        // Reset credentials so a previous request cannot leak into this instance.
        if ( !structKeyExists( arguments.dynamicProperties, "userName" ) ) {
            setUserName( "" );
        }
        if ( !structKeyExists( arguments.dynamicProperties, "password" ) ) {
            setPassword( "" );
        }

        return this;
    }


    /* ---------------------------------------------------------------------
     * PUBLIC API  (each method authenticates before running runtime methods)
     * ------------------------------------------------------------------- 
    */

    /**
    * @hint Return the JVM argument catalog for the current ColdFusion version.
    * @returnType struct
    **/
    public struct function GetArgumentCatalog() {
        try {
            requireAuth();
            return getVersionCatalog();
        } catch ( any e ) {
            logError( "GetArgumentCatalog", e );
            rethrow;
        }
    }


    /**
    * @hint List every cataloged JVM argument for this version with its current, effective and secure state.
    * @returnType array
    **/
    public array function ListJvmArguments() {
        try {
            requireAuth();
            return buildArgumentRows();
        } catch ( any e ) {
            logError( "ListJvmArguments", e );
            rethrow;
        }
    }


    /**
    * @hint Set (add or update) a single cataloged JVM argument to a validated value.
    * @returnType struct
    **/
    public struct function SetJvmArgument( required string argument, required any value ) {
        try {
            requireAuth();
            var result = applyManagedArgument( arguments.argument, arguments.value );
            logMessage( "SetJvmArgument - " & result.message );
            return result;
        } catch ( any e ) {
            logError( "SetJvmArgument(#arguments.argument#)", e );
            rethrow;
        }
    }


    /**
    * @hint Remove a cataloged JVM argument so it reverts to its documented default.
    * @returnType struct
    **/
    public struct function RemoveJvmArgument( required string argument ) {
        try {
            requireAuth();
            var result = removeManagedArgument( arguments.argument );
            logMessage( "RemoveJvmArgument - " & result.message );
            return result;
        } catch ( any e ) {
            logError( "RemoveJvmArgument(#arguments.argument#)", e );
            rethrow;
        }
    }


    /**
    * @hint Audit the configured JVM arguments and return a weighted secure score with insecure findings.
    * @returnType struct
    **/
    public struct function AuditSecurity() {
        try {
            requireAuth();
            return runAudit();
        } catch ( any e ) {
            logError( "AuditSecurity", e );
            rethrow;
        }
    }


    /**
    * @hint Harden every insecure security flag to its secure value. Defaults to a dry run.
    * @returnType struct
    **/
    public struct function ApplySecureDefaults( boolean dryRun = true ) {
        try {
            requireAuth();
            return applySecureDefaultsInternal( arguments.dryRun );
        } catch ( any e ) {
            logError( "ApplySecureDefaults(dryRun=#arguments.dryRun#)", e );
            rethrow;
        }
    }


    private struct function applySecureDefaultsInternal( boolean dryRun = true ) {
        var audit   = runAudit();
        var changes = [];

        for ( var finding in audit.findings ) {
            var change = {
                "name"          : finding.name,
                "template"      : finding.template,
                "severity"      : finding.severity,
                "fromValue"     : finding.effectiveValue,
                "toValue"       : finding.secureValue,
                "action"        : len( trim( finding.secureValue ) ) ? "set" : "remove",
                "applied"       : false
            };

            if ( !arguments.dryRun ) {
                if ( len( trim( finding.secureValue ) ) ) {
                    applyManagedArgument( finding.template, finding.secureValue );
                } else {
                    removeManagedArgument( finding.template );
                }
                change.applied = true;
            }

            arrayAppend( changes, change );
        }

        var result = {
            "dryRun"          : arguments.dryRun,
            "cfVersion"       : variables.cf_version,
            "scoreBefore"     : audit.score,
            "gradeBefore"     : audit.grade,
            "changeCount"     : arrayLen( changes ),
            "changes"         : changes,
            "restartRequired" : ( !arguments.dryRun && arrayLen( changes ) ),
            "message"         : arguments.dryRun
                ? "Dry run: #arrayLen( changes )# insecure flag(s) would be hardened. Re-run with dryRun=false to apply."
                : "#arrayLen( changes )# flag(s) hardened. Restart ColdFusion to apply the changes."
        };

        if ( !arguments.dryRun && arrayLen( changes ) ) {
            var after = runAudit();
            result[ "scoreAfter" ] = after.score;
            result[ "gradeAfter" ] = after.grade;
        }

        logMessage( "ApplySecureDefaults - " & result.message );

        return result;
    }


    /**
    * @hint Create a timestamped backup of the server jvm.config in ./_backups/ (relative to this component).
    * @returnType struct
    **/
    public struct function BackupJvmConfig() {
        try {
            requireAuth();
            var result = createConfigBackup();
            logMessage( "BackupJvmConfig - " & result.message );
            return result;
        } catch ( any e ) {
            logError( "BackupJvmConfig", e );
            rethrow;
        }
    }


    /**
    * @hint List every jvm.config backup previously written to ./_backups/, newest first.
    * @returnType array
    **/
    public array function ListJvmConfigBackups() {
        try {
            requireAuth();
            return listConfigBackups();
        } catch ( any e ) {
            logError( "ListJvmConfigBackups", e );
            rethrow;
        }
    }


    /* ---------------------------------------------------------------------
     * AUTHENTICATION  (self-contained - no external component is extended)
     * ------------------------------------------------------------------- */

    /**
    * @hint Fail closed: throw unless the caller is an authenticated ColdFusion Administrator.
    **/
    private void function requireAuth() {
        var user = getUserName();
        var pass = getPassword();
        var ok   = false;

        if ( len( user ) && len( pass ) ) {
            try {
                ok = new cfide.adminapi.administrator().login( adminPassword = pass, adminUserId = user );
            } catch ( any e ) {
                ok = false;
            }
        }

        if ( !ok ) {
            throw(
                type    = "jvmFactory.Unauthorized",
                message = "Authentication required. Provide valid ColdFusion Administrator credentials before calling this method."
            );
        }
    }


    /* ---------------------------------------------------------------------
     * CORE OPERATIONS  (private, no auth - callers above enforce it)
     * ------------------------------------------------------------------- */

    private struct function applyManagedArgument( required string argument, required any value ) {
        var versionCatalog = getVersionCatalog();
        var match = resolveFlag( versionCatalog, arguments.argument );

        if ( !match.found ) {
            throw(
                type    = "jvmFactory.UnknownArgument",
                message = "'#arguments.argument#' is not a recognized JVM argument for ColdFusion #variables.cf_version#. Only cataloged flags can be modified."
            );
        }

        if ( structKeyExists( match.meta, "removed" ) && match.meta.removed ) {
            throw(
                type    = "jvmFactory.RemovedArgument",
                message = "'#getArgName( match.template )#' was removed in this ColdFusion version and cannot be set."
            );
        }

        var type       = structKeyExists( match.meta, "type" ) ? match.meta.type : "string";
        var normalized = validateValue( arguments.value, type );
        var newArg     = buildArgument( match.template, normalized );
        var applied    = writeArgument( getArgName( match.template ), newArg );
        var row        = describeFlag( match.template, match.meta, parseCurrentArguments() );

        return {
            "success"         : true,
            "action"          : "set",
            "message"         : "Set #getArgName( match.template )#=#normalized#. Restart ColdFusion to apply the change.",
            "argument"        : newArg,
            "jvmArguments"    : applied.raw,
            "previousValue"   : applied.previousRaw,
            "restartRequired" : true,
            "item"            : row
        };
    }


    private struct function removeManagedArgument( required string argument ) {
        var versionCatalog = getVersionCatalog();
        var match = resolveFlag( versionCatalog, arguments.argument );

        if ( !match.found ) {
            throw(
                type    = "jvmFactory.UnknownArgument",
                message = "'#arguments.argument#' is not a recognized JVM argument for ColdFusion #variables.cf_version#."
            );
        }

        var applied = writeArgument( getArgName( match.template ), "" );
        var row     = describeFlag( match.template, match.meta, parseCurrentArguments() );

        return {
            "success"         : true,
            "action"          : "remove",
            "message"         : "Removed #getArgName( match.template )#. It now falls back to its default (#formatValue( match.meta, 'default' )#). Restart ColdFusion to apply the change.",
            "removedExisting" : applied.replacedExisting,
            "jvmArguments"    : applied.raw,
            "restartRequired" : true,
            "item"            : row
        };
    }


    private struct function runAudit() {
        var rows            = buildArgumentRows();
        var totalWeight     = 0;
        var secureWeight    = 0;
        var securedCount    = 0;
        var findings        = [];
        var breakingChanges = [];
        var severityCounts  = { "critical" : 0, "high" : 0, "medium" : 0, "low" : 0 };

        for ( var row in rows ) {
            if ( row.security && !row.removed && row.weight > 0 ) {
                totalWeight += row.weight;

                if ( row.secure ) {
                    secureWeight += row.weight;
                    securedCount++;
                } else {
                    arrayAppend( findings, {
                        "name"           : row.name,
                        "template"       : row.template,
                        "update"         : row.update,
                        "severity"       : row.severity,
                        "weight"         : row.weight,
                        "breaking"       : row.breaking,
                        "currentValue"   : row.currentValue,
                        "effectiveValue" : row.effectiveValue,
                        "secureValue"    : row.secureValue,
                        "recommendation" : row.recommendation
                    } );

                    if ( structKeyExists( severityCounts, row.severity ) ) {
                        severityCounts[ row.severity ]++;
                    }
                }
            }

            if ( row.breaking ) {
                arrayAppend( breakingChanges, {
                    "name"           : row.name,
                    "template"       : row.template,
                    "update"         : row.update,
                    "severity"       : row.severity,
                    "present"        : row.present,
                    "effectiveValue" : row.effectiveValue,
                    "secure"         : row.secure
                } );
            }
        }

        var score = totalWeight > 0 ? round( secureWeight / totalWeight * 100 ) : 100;

        return {
            "cfVersion"      : variables.cf_version,
            "score"          : score,
            "grade"          : gradeForScore( score ),
            "secureWeight"   : secureWeight,
            "totalWeight"    : totalWeight,
            "securedCount"   : securedCount,
            "insecureCount"  : arrayLen( findings ),
            "findings"       : findings,
            "breakingChanges": breakingChanges,
            "severityCounts" : severityCounts,
            "generated"      : now()
        };
    }


    /* ---------------------------------------------------------------------
     * JVM CONFIG BACKUP  (private, no auth - callers above enforce it)
     * ------------------------------------------------------------------- */

    /**
    * @hint Copy the live jvm.config into ./_backups/ under a timestamped, non-clobbering name.
    **/
    private struct function createConfigBackup() {
        var source = variables.jvmConfig_path;

        if ( !fileExists( source ) ) {
            throw(
                type    = "jvmFactory.MissingJvmConfig",
                message = "jvm.config not found at #source#."
            );
        }

        var dir      = ensureBackupDir();
        var stamp    = dateTimeFormat( now(), "yyyymmdd-HHnnss" );
        var fileName = "jvm.config." & stamp & ".bak";
        var target   = dir & fileName;
        var counter  = 1;

        // Two backups in the same second must not clobber each other.
        while ( fileExists( target ) ) {
            fileName = "jvm.config." & stamp & "-" & counter & ".bak";
            target   = dir & fileName;
            counter++;
        }

        fileCopy( source, target );

        var info = getFileInfo( target );

        return {
            "success"  : true,
            "message"  : "Backed up jvm.config to #fileName#.",
            "fileName" : fileName,
            "path"     : target,
            "source"   : source,
            "size"     : info.size,
            "created"  : now()
        };
    }


    /**
    * @hint Return one row per jvm.config backup in ./_backups/, newest first.
    **/
    private array function listConfigBackups() {
        var dir    = variables.backup_dir;
        var result = [];

        if ( !directoryExists( dir ) ) {
            return result;
        }

        var files = directoryList( dir, false, "query", "jvm.config.*.bak", "dateLastModified desc" );

        for ( var i = 1; i <= files.recordCount; i++ ) {
            arrayAppend( result, {
                "fileName" : files.name[ i ],
                "path"     : dir & files.name[ i ],
                "size"     : files.size[ i ],
                "modified" : files.dateLastModified[ i ]
            } );
        }

        return result;
    }


    /**
    * @hint Ensure the ./_backups/ directory exists and return its absolute path (with trailing separator).
    **/
    private string function ensureBackupDir() {
        if ( !directoryExists( variables.backup_dir ) ) {
            directoryCreate( variables.backup_dir );
        }

        return variables.backup_dir;
    }


    /* ---------------------------------------------------------------------
     * LOGGING  (delegates to ColdFusion's writeLog; never throws)
     * ------------------------------------------------------------------- */

    /**
    * @hint Write one line to the jvm_factory log. Best-effort: never lets a logging failure reach the caller.
    **/
    private void function logMessage( required string message, string type = "information" ) {
        try {
            writeLog( text = arguments.message, type = arguments.type, file = "jvm_factory" );
        } catch ( any ignored ) {}
    }


    /**
    * @hint Log a caught exception at ERROR level.
    **/
    private void function logError( required string operation, required any exception ) {
        logMessage( arguments.operation & " - " & arguments.exception.message, "error" );
    }


    /* ---------------------------------------------------------------------
     * CATALOG + ARGUMENT MODELLING
     * ------------------------------------------------------------------- */

    private struct function loadCatalog() {
        var path = variables.catalog_path;

        if ( !fileExists( path ) ) {
            // Fall back to the 2025 catalog when no file exists for the running version.
            var fallback = getDirectoryFromPath( getCurrentTemplatePath() ) & "catalog.2025.json";

            if ( !fileExists( fallback ) ) {
                throw(
                    type    = "jvmFactory.MissingCatalog",
                    message = "JVM argument catalog not found at #path# (fallback #fallback# also missing)."
                );
            }

            path = fallback;
        }

        return deserializeJSON( fileRead( path ) );
    }


    private struct function getVersionCatalog() {
        var catalog = loadCatalog();

        if ( structKeyExists( catalog, "arguments" ) && isStruct( catalog.arguments ) ) {
            return catalog.arguments;
        }

        return catalog;
    }


    private array function buildArgumentRows() {
        var versionCatalog = getVersionCatalog();
        var current        = parseCurrentArguments();
        var names          = structKeyArray( versionCatalog );
        var rows           = [];

        arraySort( names, "textNoCase" );

        for ( var template in names ) {
            arrayAppend( rows, describeFlag( template, versionCatalog[ template ], current ) );
        }

        return rows;
    }


    private struct function describeFlag( required string template, required struct meta, required struct current ) {
        var name         = getArgName( arguments.template );
        var key          = lcase( name );
        var type         = structKeyExists( arguments.meta, "type" ) ? arguments.meta.type : "string";
        var present      = structKeyExists( arguments.current.byName, key );
        var isSecurity   = structKeyExists( arguments.meta, "security" ) && arguments.meta.security;
        var removed      = structKeyExists( arguments.meta, "removed" ) && arguments.meta.removed;
        var defaultVal   = formatValue( arguments.meta, "default" );
        var secureVal    = structKeyExists( arguments.meta, "secure" ) ? formatValue( arguments.meta, "secure" ) : defaultVal;
        var currentVal   = present ? arguments.current.byName[ key ].value : "";
        var effectiveVal = present ? currentVal : defaultVal;
        var isSecure     = valuesMatch( effectiveVal, secureVal, type );
        var status       = removed ? "removed" : ( !isSecurity ? "informational" : ( isSecure ? "secure" : "insecure" ) );

        return {
            "name"           : name,
            "template"       : arguments.template,
            "type"           : type,
            "update"         : structKeyExists( arguments.meta, "update" ) ? arguments.meta.update : 0,
            "description"    : structKeyExists( arguments.meta, "description" ) ? arguments.meta.description : "",
            "recommendation" : structKeyExists( arguments.meta, "recommendation" ) ? arguments.meta.recommendation : "",
            "security"       : isSecurity,
            "severity"       : structKeyExists( arguments.meta, "severity" ) ? arguments.meta.severity : "none",
            "weight"         : structKeyExists( arguments.meta, "weight" ) ? arguments.meta.weight : 0,
            "breaking"       : structKeyExists( arguments.meta, "breaking" ) && arguments.meta.breaking,
            "removed"        : removed,
            "default"        : defaultVal,
            "secureValue"    : secureVal,
            "present"        : present,
            "currentValue"   : currentVal,
            "effectiveValue" : effectiveVal,
            "secure"         : ( isSecurity && !removed ) ? isSecure : "",
            "status"         : status,
            "argument"       : present
                ? arguments.current.byName[ key ].argument
                : buildArgument( arguments.template, effectiveVal )
        };
    }


    private struct function resolveFlag( required struct catalog, required string requested ) {
        var reqTemplate = trim( arguments.requested );
        var reqName     = getArgName( reqTemplate );

        if ( structKeyExists( arguments.catalog, reqTemplate ) ) {
            return { "found" : true, "template" : reqTemplate, "meta" : arguments.catalog[ reqTemplate ] };
        }

        for ( var key in arguments.catalog ) {
            if ( compareNoCase( getArgName( key ), reqName ) == 0 ) {
                return { "found" : true, "template" : key, "meta" : arguments.catalog[ key ] };
            }
        }

        return { "found" : false, "template" : reqTemplate, "meta" : {} };
    }


    /* ---------------------------------------------------------------------
     * JVMArguments PARSING + WRITING  (mirrors the legacy client's behaviour)
     * ------------------------------------------------------------------- */

    private struct function parseCurrentArguments() {
        var runtime = getRuntime();
        var raw     = "";

        try {
            raw = trim( runtime.GetJvmProperty( "JVMArguments" ) );
        } catch ( any e ) {
            raw = "";
        }

        var list   = len( raw ) ? listToArray( raw, chr( 32 ) ) : [];
        var byName = {};

        for ( var token in list ) {
            var arg = trim( token );

            if ( !len( arg ) ) {
                continue;
            }

            var name = getArgName( arg );
            byName[ lcase( name ) ] = {
                "argument" : arg,
                "name"     : name,
                "value"    : getArgValue( arg )
            };
        }

        return { "raw" : raw, "list" : list, "byName" : byName };
    }


    /**
    * @hint Replace/remove a single flag while preserving every other JVM argument (heap, GC, custom flags).
    **/
    private struct function writeArgument( required string argName, string newArgument = "" ) {
        var runtime          = getRuntime();
        var current          = parseCurrentArguments();
        var next             = [];
        var replacedExisting = false;

        for ( var token in current.list ) {
            var arg = trim( token );

            if ( !len( arg ) ) {
                continue;
            }

            if ( compareNoCase( getArgName( arg ), arguments.argName ) == 0 ) {
                replacedExisting = true;
                continue;
            }

            arrayAppend( next, arg );
        }

        if ( len( trim( arguments.newArgument ) ) ) {
            arrayAppend( next, trim( arguments.newArgument ) );
        }

        var nextRaw = arrayToList( next, chr( 32 ) );
        runtime.SetJvmProperty( "JVMArguments", nextRaw );

        return {
            "previousRaw"      : current.raw,
            "raw"              : nextRaw,
            "replacedExisting" : replacedExisting
        };
    }


    private string function getArgName( required string argumentText ) {
        var text     = trim( arguments.argumentText );
        var equalsAt = find( "=", text );

        return equalsAt > 0 ? left( text, equalsAt - 1 ) : text;
    }


    private string function getArgValue( required string argumentText ) {
        var text     = trim( arguments.argumentText );
        var equalsAt = find( "=", text );

        return equalsAt > 0 ? mid( text, equalsAt + 1, len( text ) ) : "";
    }


    private string function buildArgument( required string template, string value = "" ) {
        var tpl       = trim( arguments.template );
        var valueText = trim( arguments.value );

        if ( find( "<timezone>", tpl ) ) {
            return replace( tpl, "<timezone>", len( valueText ) ? valueText : "GMT", "all" );
        }

        if ( find( "=", tpl ) ) {
            return len( valueText ) ? getArgName( tpl ) & "=" & valueText : getArgName( tpl );
        }

        return len( valueText ) ? tpl & "=" & valueText : tpl;
    }


    /* ---------------------------------------------------------------------
     * VALUE VALIDATION + NORMALISATION  (security boundary)
     * ------------------------------------------------------------------- */

    /**
    * @hint Validate an incoming value against its declared type and reject anything that could inject a flag.
    **/
    private string function validateValue( required any value, required string type ) {
        var text = isSimpleValue( arguments.value ) ? trim( toString( arguments.value ) ) : "";

        // JVMArguments are space-delimited; forbid whitespace so a value cannot smuggle in extra flags.
        if ( reFind( "[[:space:]]", text ) ) {
            throw(
                type    = "jvmFactory.InvalidValue",
                message = "JVM argument values may not contain whitespace."
            );
        }

        switch ( arguments.type ) {
            case "boolean":
                if ( !listFindNoCase( "true,false,yes,no,on,off,1,0", text ) ) {
                    throw( type = "jvmFactory.InvalidValue", message = "Expected a boolean value (true/false)." );
                }
                return normalizeBoolean( text );

            case "number":
                if ( !isNumeric( text ) ) {
                    throw( type = "jvmFactory.InvalidValue", message = "Expected a numeric value." );
                }
                return text;

            default:
                // string / list: allow the safe punctuation used by TLS lists, serialFilter, timezones, packages.
                if ( len( text ) && !reFind( "^[A-Za-z0-9_.,:;=/*!\-]+$", text ) ) {
                    throw( type = "jvmFactory.InvalidValue", message = "Value contains unsupported characters." );
                }
                return text;
        }
    }


    private string function normalizeBoolean( required any value ) {
        if ( isBoolean( arguments.value ) ) {
            return arguments.value ? "true" : "false";
        }

        var text = trim( toString( arguments.value ) );

        if ( listFindNoCase( "true,yes,on,1", text ) ) {
            return "true";
        }

        if ( listFindNoCase( "false,no,off,0", text ) ) {
            return "false";
        }

        return lcase( text );
    }


    private string function formatValue( required struct meta, required string key ) {
        if ( !structKeyExists( arguments.meta, arguments.key ) ) {
            return "";
        }

        var raw = arguments.meta[ arguments.key ];

        if ( isNull( raw ) ) {
            return "";
        }

        var type = structKeyExists( arguments.meta, "type" ) ? arguments.meta.type : "string";

        if ( type == "boolean" ) {
            return normalizeBoolean( raw );
        }

        return trim( toString( raw ) );
    }


    private boolean function valuesMatch( required string current, required string target, string type = "string" ) {
        if ( arguments.type == "boolean" ) {
            return normalizeBoolean( arguments.current ) == normalizeBoolean( arguments.target );
        }

        if ( arguments.type == "number" ) {
            if ( isNumeric( arguments.current ) && isNumeric( arguments.target ) ) {
                return val( arguments.current ) == val( arguments.target );
            }
            return compare( trim( arguments.current ), trim( arguments.target ) ) == 0;
        }

        return compareNoCase( trim( arguments.current ), trim( arguments.target ) ) == 0;
    }


    private string function gradeForScore( required numeric score ) {
        if ( arguments.score >= 90 ) return "A";
        if ( arguments.score >= 80 ) return "B";
        if ( arguments.score >= 70 ) return "C";
        if ( arguments.score >= 60 ) return "D";
        return "F";
    }


    private any function getRuntime() {
        return new cfide.adminapi.runtime();
    }

}
