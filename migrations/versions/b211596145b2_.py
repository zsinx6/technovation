"""empty message

Revision ID: b211596145b2
Revises: 05ae56639e0a
Create Date: 2020-03-25 20:09:29.679589

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b211596145b2'
down_revision = '05ae56639e0a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('messages',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('category', sa.String(length=60), nullable=False),
    sa.Column('text', sa.String(length=2000), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('message')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('message',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('category', sa.VARCHAR(length=60), autoincrement=False, nullable=False),
    sa.Column('text', sa.VARCHAR(length=500), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='message_pkey')
    )
    op.drop_table('messages')
    # ### end Alembic commands ###