package puli.xaidaz.config;

import org.hibernate.jpa.HibernatePersistenceProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@EnableTransactionManagement
public class PersistanceConfiguration {


    private static final String DB_USER = "puli-app-user";
    private static final String DB_PASSWORD = "skat";
    private static final String DB_URL_LOCAL = "jdbc:mysql://localhost:3306/PuliDb";
    private static final String DB_URL_ENV = "jdbc:mysql://puli-mysql:3306/PuliDb";
    private static final String DB_URL_ATTRIBUTES = "?useSSL=false&allowPublicKeyRetrieval=true&autoReconnect=true";

    private static final String[] ENTITYMANAGER_PACKAGES_TO_SCAN = {"puli.xaidaz.jpa.entity"};

    @Value("${environment}")
    private String environment;

    @Bean
    public DataSource dataSource() {
        System.out.println("Initializing datasource in environment: " +environment)
        ;
        DataSourceBuilder builder = DataSourceBuilder.create();
        builder.driverClassName("com.mysql.cj.jdbc.Driver");
        builder.username(DB_USER);
        builder.password(DB_PASSWORD);

        if (environment.equalsIgnoreCase("local")) {
            builder.url(DB_URL_LOCAL + DB_URL_ATTRIBUTES);
        } else {
            builder.url(DB_URL_ENV + DB_URL_ATTRIBUTES);
        }
        return builder.build();
    }

    private HibernateJpaVendorAdapter vendorAdaptor() {
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setShowSql(true);
        return vendorAdapter;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean entityManagerFactoryBean = new LocalContainerEntityManagerFactoryBean();
        entityManagerFactoryBean.setJpaVendorAdapter(vendorAdaptor());
        entityManagerFactoryBean.setDataSource(dataSource());
        entityManagerFactoryBean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        entityManagerFactoryBean.setPackagesToScan(ENTITYMANAGER_PACKAGES_TO_SCAN);
        entityManagerFactoryBean.setJpaProperties(jpaHibernateProperties());
        return entityManagerFactoryBean;
    }

    private Properties jpaHibernateProperties() {
        Properties properties = new Properties();
        properties.put("hibernate.dialect", "org.hibernate.dialect.MySQL5InnoDBDialect");
        properties.setProperty("hibernate.show_sql", "false");
        return properties;
    }
}
