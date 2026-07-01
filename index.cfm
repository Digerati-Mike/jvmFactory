<cfscript>
    // initialize the jvmFactory
    jvmFactory  = new jvmFactory( { 
        "userName" : "{{userName}}", 
        "password" : "{{password}}", 
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