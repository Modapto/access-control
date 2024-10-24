package gr.atc.modapto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.ThreadPoolExecutor;

/*
* Configuration of Thread Pool in order to reuse the threads for the async processing
 */
@Configuration
@EnableAsync
public class AsyncConfiguration {

    @Bean(name = "asyncPoolTaskExecutor")
    public ThreadPoolTaskExecutor executor() {
        ThreadPoolTaskExecutor taskExecutor = new ThreadPoolTaskExecutor();
        taskExecutor.setCorePoolSize(10); // Number of core threads
        taskExecutor.setMaxPoolSize(100); // Maximum number of maintained threads
        taskExecutor.setQueueCapacity(50); // Cache queue
        taskExecutor.setKeepAliveSeconds(200); // Allowed idle time for non-core threads
        // Retry async methods if they fails
        taskExecutor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        taskExecutor.initialize();
        return taskExecutor;
    }
}
