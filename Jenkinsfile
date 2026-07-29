pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh '''
                    cmake -S . -B build
                    cmake --build build
                '''
            }
        }

        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'build/fast_path/ips_loader, build/fast_path/ips_injector', fingerprint: true
            }
        }
    }
}
