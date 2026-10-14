<cfscript>


    tmpConfigFile = ExpandPath('.\config.json');


    if( !FileExists( tmpConfigFile ) ){  

        WriteOutput( '

            <div style="text-align: center; font-weight: bold;">
                <span style="color:red">!!!WARNING!!!</span> 
                <hr />
                CFAdmin credentials are needed for this component.
            </div>
            <hr />
            <div style="text-align: center;">
                For a proof of concept or testing populate the config.example.json and rename to config.json. Do not leave this code with plain text credentials in production ESPECIALLY on a public web root on a web server.
            </div>


        ' );
        abort;
    }
    // read the config.json file for the jvmFactory credentials
    jvmFactoryConfig = deserializeJSON( fileRead( tmpConfigFile ) );
    
    // initialize the jvmFactory
    jvmFactory  = new jvmFactory( { 
        "userName" : jvmFactoryConfig.userName, 
        "password" : jvmFactoryConfig.password, 
        "backup_dir" : ExpandPath('.\_backups\') 
    } );
    

    // 1. What exactly is insecure?
    audit = jvmFactory.AuditSecurity();

    // 2. Back up jvm.config before making any changes.
    backup = jvmFactory.BackupJvmConfig();

    // 3. Preview the hardening, then apply it.
    plan    = jvmFactory.ApplySecureDefaults();
    applied = jvmFactory.ApplySecureDefaults( dryRun = false );

    // 4. Restart ColdFusion for the JVM changes to take effect.
    

    // Output the results of the audit, backup, and hardening plan.
    writeDump( var = SecurityAudit, top = 5 );
    writeDump( var = ArgumentCatalog, top = 5 );
</cfscript>