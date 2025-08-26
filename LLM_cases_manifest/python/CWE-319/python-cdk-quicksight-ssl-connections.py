import aws_cdk as cdk
from aws_cdk import (
    aws_quicksight as quicksight,
    Stack,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct
import os

# True Positives (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableMySQLDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-mysql-source",
        name="Vulnerable MySQL Source",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql-database.example.com",
                port=3306,
                database="sales_db",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="admin",
                password="password123"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a QuickSight PostgreSQL data source with SSL explicitly disabled
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerablePostgreSQLDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-postgres-source",
        name="Vulnerable PostgreSQL Source",
        type="POSTGRESQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            postgresql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                host="postgres.example.com",
                port=5432,
                database="analytics",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="db_user",
                password="db_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a QuickSight Amazon RDS data source without SSL configuration
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableRDSDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-rds-source",
        name="Vulnerable RDS Source",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="rds-instance.abcdefg.us-west-2.rds.amazonaws.com",
                port=3306,
                database="customers"
                # ruleid: python-cdk-quicksight-ssl-connections
                # Missing SSL configuration
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="rds_user",
                password="rds_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a QuickSight SQL Server data source with SSL disabled
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableSQLServerDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-sqlserver-source",
        name="Vulnerable SQL Server Source",
        type="SQLSERVER",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                host="sqlserver.example.com",
                port=1433,
                database="reporting",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="sql_user",
                password="sql_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a QuickSight MariaDB data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableMariaDBDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-mariadb-source",
        name="Vulnerable MariaDB Source",
        type="MARIADB",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                host="mariadb.example.com",
                port=3306,
                database="inventory",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="maria_user",
                password="maria_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a QuickSight Teradata data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableTeradataDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-teradata-source",
        name="Vulnerable Teradata Source",
        type="TERADATA",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                host="teradata.example.com",
                port=1025,
                database="warehouse",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="teradata_user",
                password="teradata_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a QuickSight Presto data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerablePrestoDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-presto-source",
        name="Vulnerable Presto Source",
        type="PRESTO",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                host="presto.example.com",
                port=8889,
                catalog="hive",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="presto_user",
                password="presto_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a QuickSight Snowflake data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableSnowflakeDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-snowflake-source",
        name="Vulnerable Snowflake Source",
        type="SNOWFLAKE",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                host="snowflake.example.com",
                database="analytics",
                warehouse="compute_wh",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="snowflake_user",
                password="snowflake_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a QuickSight Aurora data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableAuroraDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-aurora-source",
        name="Vulnerable Aurora Source",
        type="AURORA",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                host="aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
                port=3306,
                database="finance",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="aurora_user",
                password="aurora_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a QuickSight Aurora PostgreSQL data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableAuroraPostgreSQLDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-aurora-pg-source",
        name="Vulnerable Aurora PostgreSQL Source",
        type="AURORA_POSTGRESQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            aurora_postgresql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                host="aurora-pg.cluster-abc.us-west-2.rds.amazonaws.com",
                port=5432,
                database="marketing",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="aurora_pg_user",
                password="aurora_pg_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a QuickSight Redshift data source without SSL
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableRedshiftDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-redshift-source",
        name="Vulnerable Redshift Source",
        type="REDSHIFT",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                host="redshift-cluster.abcxyz.us-east-1.redshift.amazonaws.com",
                port=5439,
                database="dwh",
                # ruleid: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="redshift_user",
                password="redshift_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source with SSL disabled in a stack
    stack = Stack(scope, "VulnerableMySQLStack")
    
    # ruleid: python-cdk-quicksight-ssl-connections
    data_source = quicksight.CfnDataSource(
        stack,
        "VulnerableMySQLDataSource",
        aws_account_id="123456789012",
        data_source_id="vulnerable-mysql-source-stack",
        name="Vulnerable MySQL Source in Stack",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql.example.com",
                port=3306,
                database="products",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="mysql_user",
                password="mysql_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a QuickSight PostgreSQL data source with SSL disabled in a function
    def create_data_source():
        # ruleid: python-cdk-quicksight-ssl-connections
        return quicksight.CfnDataSource(
            scope,
            "VulnerablePostgreSQLDataSourceInFunction",
            aws_account_id="123456789012",
            data_source_id="vulnerable-postgres-source-func",
            name="Vulnerable PostgreSQL Source in Function",
            type="POSTGRESQL",
            data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
                postgresql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                    host="postgres.example.com",
                    port=5432,
                    database="users",
                    ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                        disable_ssl=True
                    )
                )
            ),
            credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
                credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                    username="pg_user",
                    password="pg_password"
                )
            )
        )
    
    return create_data_source()

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source with SSL disabled using variables
    disable_ssl_value = True
    
    # ruleid: python-cdk-quicksight-ssl-connections
    data_source = quicksight.CfnDataSource(
        scope,
        "VulnerableMySQLDataSourceWithVariable",
        aws_account_id="123456789012",
        data_source_id="vulnerable-mysql-source-var",
        name="Vulnerable MySQL Source with Variable",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql-db.example.com",
                port=3306,
                database="orders",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=disable_ssl_value
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="orders_user",
                password="orders_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating multiple QuickSight data sources with SSL disabled
    data_sources = []
    
    # MySQL data source
    # ruleid: python-cdk-quicksight-ssl-connections
    mysql_source = quicksight.CfnDataSource(
        scope,
        "VulnerableMySQLDataSourceMulti",
        aws_account_id="123456789012",
        data_source_id="vulnerable-mysql-multi",
        name="Vulnerable MySQL Source Multi",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql-multi.example.com",
                port=3306,
                database="multi_db",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=True
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="multi_user",
                password="multi_password"
            )
        )
    )
    data_sources.append(mysql_source)
    
    return data_sources

# True Negatives (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureMySQLDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-mysql-source",
        name="Secure MySQL Source",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql-database.example.com",
                port=3306,
                database="sales_db",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="admin",
                password="password123"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a QuickSight PostgreSQL data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecurePostgreSQLDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-postgres-source",
        name="Secure PostgreSQL Source",
        type="POSTGRESQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            postgresql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                host="postgres.example.com",
                port=5432,
                database="analytics",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="db_user",
                password="db_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a QuickSight Amazon RDS data source with SSL explicitly enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureRDSDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-rds-source",
        name="Secure RDS Source",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="rds-instance.abcdefg.us-west-2.rds.amazonaws.com",
                port=3306,
                database="customers",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="rds_user",
                password="rds_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a QuickSight SQL Server data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureSQLServerDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-sqlserver-source",
        name="Secure SQL Server Source",
        type="SQLSERVER",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            sql_server_parameters=quicksight.CfnDataSource.SqlServerParametersProperty(
                host="sqlserver.example.com",
                port=1433,
                database="reporting",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="sql_user",
                password="sql_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a QuickSight MariaDB data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureMariaDBDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-mariadb-source",
        name="Secure MariaDB Source",
        type="MARIADB",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            maria_db_parameters=quicksight.CfnDataSource.MariaDbParametersProperty(
                host="mariadb.example.com",
                port=3306,
                database="inventory",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="maria_user",
                password="maria_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a QuickSight Teradata data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureTeradataDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-teradata-source",
        name="Secure Teradata Source",
        type="TERADATA",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            teradata_parameters=quicksight.CfnDataSource.TeradataParametersProperty(
                host="teradata.example.com",
                port=1025,
                database="warehouse",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="teradata_user",
                password="teradata_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a QuickSight Presto data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecurePrestoDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-presto-source",
        name="Secure Presto Source",
        type="PRESTO",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            presto_parameters=quicksight.CfnDataSource.PrestoParametersProperty(
                host="presto.example.com",
                port=8889,
                catalog="hive",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="presto_user",
                password="presto_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a QuickSight Snowflake data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureSnowflakeDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-snowflake-source",
        name="Secure Snowflake Source",
        type="SNOWFLAKE",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            snowflake_parameters=quicksight.CfnDataSource.SnowflakeParametersProperty(
                host="snowflake.example.com",
                database="analytics",
                warehouse="compute_wh",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="snowflake_user",
                password="snowflake_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a QuickSight Aurora data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureAuroraDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-aurora-source",
        name="Secure Aurora Source",
        type="AURORA",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            aurora_parameters=quicksight.CfnDataSource.AuroraParametersProperty(
                host="aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
                port=3306,
                database="finance",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="aurora_user",
                password="aurora_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a QuickSight Aurora PostgreSQL data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureAuroraPostgreSQLDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-aurora-pg-source",
        name="Secure Aurora PostgreSQL Source",
        type="AURORA_POSTGRESQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            aurora_postgresql_parameters=quicksight.CfnDataSource.AuroraPostgreSqlParametersProperty(
                host="aurora-pg.cluster-abc.us-west-2.rds.amazonaws.com",
                port=5432,
                database="marketing",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="aurora_pg_user",
                password="aurora_pg_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a QuickSight Redshift data source with SSL enabled
    data_source = quicksight.CfnDataSource(
        scope,
        "SecureRedshiftDataSource",
        aws_account_id="123456789012",
        data_source_id="secure-redshift-source",
        name="Secure Redshift Source",
        type="REDSHIFT",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            redshift_parameters=quicksight.CfnDataSource.RedshiftParametersProperty(
                host="redshift-cluster.abcxyz.us-east-1.redshift.amazonaws.com",
                port=5439,
                database="dwh",
                # ok: python-cdk-quicksight-ssl-connections
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="redshift_user",
                password="redshift_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source with SSL enabled in a stack
    stack = Stack(scope, "SecureMySQLStack")
    
    # ok: python-cdk-quicksight-ssl-connections
    data_source = quicksight.CfnDataSource(
        stack,
        "SecureMySQLDataSourceInStack",
        aws_account_id="123456789012",
        data_source_id="secure-mysql-source-stack",
        name="Secure MySQL Source in Stack",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql.example.com",
                port=3306,
                database="products",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="mysql_user",
                password="mysql_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a QuickSight PostgreSQL data source with SSL enabled using a variable
    disable_ssl_value = False
    
    # ok: python-cdk-quicksight-ssl-connections
    data_source = quicksight.CfnDataSource(
        scope,
        "SecurePostgreSQLDataSourceWithVariable",
        aws_account_id="123456789012",
        data_source_id="secure-postgres-source-var",
        name="Secure PostgreSQL Source with Variable",
        type="POSTGRESQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            postgresql_parameters=quicksight.CfnDataSource.PostgreSqlParametersProperty(
                host="postgres.example.com",
                port=5432,
                database="users",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=disable_ssl_value
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="pg_user",
                password="pg_password"
            )
        )
    )
    return data_source

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a QuickSight MySQL data source with SSL enabled in a function
    def create_data_source():
        # ok: python-cdk-quicksight-ssl-connections
        return quicksight.CfnDataSource(
            scope,
            "SecureMySQLDataSourceInFunction",
            aws_account_id="123456789012",
            data_source_id="secure-mysql-source-func",
            name="Secure MySQL Source in Function",
            type="MYSQL",
            data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
                mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                    host="mysql-db.example.com",
                    port=3306,
                    database="orders",
                    ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                        disable_ssl=False
                    )
                )
            ),
            credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
                credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                    username="orders_user",
                    password="orders_password"
                )
            )
        )
    
    return create_data_source()

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating multiple QuickSight data sources with SSL enabled
    data_sources = []
    
    # MySQL data source
    # ok: python-cdk-quicksight-ssl-connections
    mysql_source = quicksight.CfnDataSource(
        scope,
        "SecureMySQLDataSourceMulti",
        aws_account_id="123456789012",
        data_source_id="secure-mysql-multi",
        name="Secure MySQL Source Multi",
        type="MYSQL",
        data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
            mysql_parameters=quicksight.CfnDataSource.MySQLParametersProperty(
                host="mysql-multi.example.com",
                port=3306,
                database="multi_db",
                ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                    disable_ssl=False
                )
            )
        ),
        credentials=quicksight.CfnDataSource.DataSourceCredentialsProperty(
            credential_pair=quicksight.CfnDataSource.CredentialPairProperty(
                username="multi_user",
                password="multi_password"
            )
        )
    )
    data_sources.append(mysql_source)
    
    return data_sources
# {/fact}