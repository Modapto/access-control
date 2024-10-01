package gr.atc.modapto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

@SpringBootTest
class ModaptoUserManagerApplicationTests {

@Test
void contextLoads() {
    Assertions.assertNotNull(ApplicationContext.class);
}

}
