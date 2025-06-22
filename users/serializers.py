from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'full_name', 'phone_number', 'address']
        
    def update(self, instance, validated_data):
        """
        update and return instance data of users.
        """
        instance.username = validated_data.get('username', instance.username)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.address = validated_data.get('address', instance.address)
        instance.save()
        return instance