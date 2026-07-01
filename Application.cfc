component {
    
    this.name = "JVMFactory-v1.0.0";

    this.applicationTimeout     = createTimeSpan(1, 0, 0, 0);

    this.applicationManagement  = true;

    this.sessionManagement      = false;

    public boolean function onApplicationStart() {

        Application.rootPath = ExpandPath('.\')

        if( !DirectoryExists( Application.rootPath & "_backups" ) ){ DirectoryCreate( Application.rootPath & "_backups" ); }
        if( !DirectoryExists( Application.rootPath & "_logs" ) ){ DirectoryCreate( Application.rootPath & "_logs" ); }

        return true;
    }

    public void function onError(required any exception, required string eventName) {
        
        writeDump( var = exception, top = 5 );
        return;
    }
}