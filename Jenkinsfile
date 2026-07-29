pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Hello') {
            steps {
                echo 'Jenkins is connected to the Intrusion-Prevention-System repo.'
                sh 'ls -la'
            }
        }
    }
}
